use actix_cors::Cors;
use actix_multipart::Multipart;
use actix_web::{web, App, HttpResponse, HttpServer};
use futures::StreamExt;            // Multipart / Field 스트림에 .next() 사용
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use tokio::process::Command;       // subprocess → tokio async Command

// ════════════════════════════════════════════════════════════════
// 상수
// ════════════════════════════════════════════════════════════════

const UPLOAD_DIR: &str = "uploads";

// ════════════════════════════════════════════════════════════════
// 요청 / 응답 모델
// ════════════════════════════════════════════════════════════════

/// POST /upload 응답
#[derive(Serialize)]
struct UploadResponse {
    filename: String,
    status:   String,
}

/// GET /packets 쿼리 파라미터
#[derive(Deserialize)]
struct PacketQuery {
    filename: String,
    page:     Option<i64>,   // 기본값 1
    limit:    Option<i64>,   // 기본값 50
}

/// 단일 패킷 행
#[derive(Serialize)]
struct Packet {
    id:        String,
    src:       String,
    dst:       String,
    sport:     String,
    dport:     String,
    stream_id: String,
    len:       String,
}

/// GET /packets 응답
#[derive(Serialize)]
struct PacketResponse {
    packets: Vec<Packet>,
    total:   usize,
    page:    i64,
    limit:   i64,
}

/// GET /stream/{id} · /analyze-secs/{id} 공통 쿼리 파라미터
#[derive(Deserialize)]
struct StreamQuery {
    filename: String,
}

/// GET /stream/{id} 응답
#[derive(Serialize)]
struct StreamFollowResponse {
    content: String,
}

/// 파싱된 HSMS 메시지 한 건
#[derive(Serialize)]
struct HsmsMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id:  Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream:      Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    func:        Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wbit:        Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_byte: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stype:       Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_hex:    Option<String>,
    /// 파싱 중 오류 발생 시만 채움
    #[serde(skip_serializing_if = "Option::is_none")]
    error:       Option<String>,
}

/// GET /analyze-secs/{id} 응답
#[derive(Serialize)]
struct SecsResponse {
    messages: Vec<HsmsMessage>,
}

// ════════════════════════════════════════════════════════════════
// HSMS / SECS-II 파서
//   Python의 struct.unpack(">H", …) / struct.unpack(">I", …)
//   → Rust의 u16::from_be_bytes / u32::from_be_bytes 로 변환
// ════════════════════════════════════════════════════════════════

fn parse_hsms_secs2(payload_hex: &str) -> Option<HsmsMessage> {
    // hex 문자열 → 바이트 배열
    let data = match hex::decode(payload_hex.trim()) {
        Ok(d)  => d,
        Err(e) => {
            return Some(HsmsMessage {
                session_id: None, stream: None, func: None,
                wbit: None, system_byte: None, stype: None,
                data_hex: None,
                error: Some(e.to_string()),
            });
        }
    };

    if data.len() < 14 {
        return None;                  // 최소 길이(4 Length + 10 Header) 미충족
    }

    // Header는 바이트 4 ~ 13 (10 bytes)
    let hdr = &data[4..14];

    let session_id  = u16::from_be_bytes([hdr[0], hdr[1]]);
    let stream_byte = hdr[2];
    let wbit        = (stream_byte & 0x80) >> 7;
    let stream      = stream_byte & 0x7F;
    let func        = hdr[3];
    let stype       = hdr[5];                                        // PType은 hdr[4]
    let system_byte = u32::from_be_bytes([hdr[6], hdr[7], hdr[8], hdr[9]]);

    // 데이터 영역 (14바이트 이후)
    let data_hex = if data.len() > 14 {
        hex::encode(&data[14..])
    } else {
        String::new()
    };

    Some(HsmsMessage {
        session_id:  Some(session_id),
        stream:      Some(stream),
        func:        Some(func),
        wbit:        Some(wbit),
        system_byte: Some(system_byte),
        stype:       Some(stype),
        data_hex:    Some(data_hex),
        error:       None,
    })
}

// ════════════════════════════════════════════════════════════════
// 공통 헬퍼
// ════════════════════════════════════════════════════════════════

/// tshark 실행 실패 시 500 응답 생성
fn tshark_err(e: std::io::Error) -> HttpResponse {
    HttpResponse::InternalServerError()
        .json(serde_json::json!({"error": format!("tshark 실행 오류: {}", e)}))
}

// ════════════════════════════════════════════════════════════════
// 핸들러
// ════════════════════════════════════════════════════════════════

/// POST /upload  —  pcap 파일 업로드
async fn upload_pcap(mut payload: Multipart) -> HttpResponse {
    let mut filename = String::new();

    // Multipart 스트림에서 파일 필드를 하나씩 처리
    while let Some(Ok(mut field)) = payload.next().await {
        let disposition = field.content_disposition();
        let fname = disposition
            .get_filename()
            .unwrap_or("unknown")
            .to_string();
        filename = fname.clone();

        let filepath = format!("{}/{}", UPLOAD_DIR, fname);
        let mut file = match fs::File::create(&filepath) {
            Ok(f)  => f,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("파일 생성 실패: {}", e)}));
            }
        };

        // 청크 단위로 디스크 기록
        while let Some(Ok(chunk)) = field.next().await {
            if let Err(e) = file.write_all(&chunk) {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"error": format!("파일 기록 실패: {}", e)}));
            }
        }
    }

    HttpResponse::Ok().json(UploadResponse {
        filename,
        status: "uploaded".to_string(),
    })
}

/// GET /packets?filename=…&page=…&limit=…  —  페이지네이션된 패킷 목록
async fn get_packets(query: web::Query<PacketQuery>) -> HttpResponse {
    let filename = &query.filename;
    let page     = query.page.unwrap_or(1);
    let limit    = query.limit.unwrap_or(50);
    let file_path = format!("{}/{}", UPLOAD_DIR, filename);

    // ── 1단계: 전체 TCP 패킷의 frame.number 목록 가져오기 ──
    let count_output = match Command::new("tshark")
        .args(["-r", &file_path, "-T", "fields", "-e", "frame.number", "-Y", "tcp"])
        .output()
        .await
    {
        Ok(o)  => o,
        Err(e) => return tshark_err(e),
    };

    let stdout      = String::from_utf8_lossy(&count_output.stdout);
    let total_lines: Vec<&str> = stdout.trim().split('\n').filter(|l| !l.is_empty()).collect();
    let total_count = total_lines.len();

    // ── 2단계: 페이지 범위 계산 ──
    let start = ((page - 1) * limit) as usize;
    let end   = (start + limit as usize).min(total_count);

    if start >= total_count {
        return HttpResponse::Ok().json(PacketResponse {
            packets: vec![], total: total_count, page, limit,
        });
    }

    let target_frames = &total_lines[start..end];

    // ── 3단계: 선택된 frame만 필터링하여 상세 정보 조회 ──
    //   예: "frame.number == 101 || frame.number == 102 || …"
    let frame_filter: String = target_frames
        .iter()
        .map(|f| format!("frame.number == {}", f))
        .collect::<Vec<_>>()
        .join(" || ");

    let packet_output = match Command::new("tshark")
        .args([
            "-r", &file_path,
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.stream",
            "-e", "frame.len",
            "-Y", &frame_filter,
        ])
        .output()
        .await
    {
        Ok(o)  => o,
        Err(e) => return tshark_err(e),
    };

    let stdout  = String::from_utf8_lossy(&packet_output.stdout);
    let packets: Vec<Packet> = stdout
        .trim()
        .split('\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() >= 7 {
                Some(Packet {
                    id:        f[0].into(),
                    src:       f[1].into(),
                    dst:       f[2].into(),
                    sport:     f[3].into(),
                    dport:     f[4].into(),
                    stream_id: f[5].into(),
                    len:       f[6].into(),
                })
            } else {
                None
            }
        })
        .collect();

    HttpResponse::Ok().json(PacketResponse { packets, total: total_count, page, limit })
}

/// GET /stream/{stream_id}?filename=…  —  TCP 스트림 조회
async fn follow_stream(
    path:  web::Path<i64>,
    query: web::Query<StreamQuery>,
) -> HttpResponse {
    let stream_id = path.into_inner();
    let file_path = format!("{}/{}", UPLOAD_DIR, &query.filename);
    let z_arg     = format!("follow,tcp,ascii,{}", stream_id);

    let output = match Command::new("tshark")
        .args(["-r", &file_path, "-z", &z_arg])
        .output()
        .await
    {
        Ok(o)  => o,
        Err(e) => return tshark_err(e),
    };

    HttpResponse::Ok().json(StreamFollowResponse {
        content: String::from_utf8_lossy(&output.stdout).to_string(),
    })
}

/// GET /analyze-secs/{stream_id}?filename=…  —  HSMS/SECS-II 메시지 분석
async fn analyze_secs(
    path:  web::Path<i64>,
    query: web::Query<StreamQuery>,
) -> HttpResponse {
    let stream_id = path.into_inner();
    let file_path = format!("{}/{}", UPLOAD_DIR, &query.filename);
    let y_filter  = format!("tcp.stream eq {}", stream_id);

    let output = match Command::new("tshark")
        .args([
            "-r", &file_path,
            "-Y", &y_filter,
            "-T", "fields",
            "-e", "tcp.payload",
        ])
        .output()
        .await
    {
        Ok(o)  => o,
        Err(e) => return tshark_err(e),
    };

    let stdout   = String::from_utf8_lossy(&output.stdout);
    let messages: Vec<HsmsMessage> = stdout
        .trim()
        .split('\n')
        .filter(|p| !p.is_empty())
        .filter_map(|p| parse_hsms_secs2(p))
        .collect();

    HttpResponse::Ok().json(SecsResponse { messages })
}

// ════════════════════════════════════════════════════════════════
// main — 서버 부팅
// ════════════════════════════════════════════════════════════════

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // uploads 디렉토리 생성 (없으면)
    fs::create_dir_all(UPLOAD_DIR)?;

    println!("🚀  pcap-analyzer 서버 시작 … http://0.0.0.0:8888");

    HttpServer::new(|| {
        // CORS: 모든 origin / method / header 허용 (Python 코드와 동일)
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            // ── 라우트 등록 (Python의 @app.post / @app.get과 대응) ──
            .route("/upload",                  web::post().to(upload_pcap))
            .route("/packets",                 web::get().to(get_packets))
            .route("/stream/{stream_id}",      web::get().to(follow_stream))
            .route("/analyze-secs/{stream_id}", web::get().to(analyze_secs))
    })
    .bind("0.0.0.0:8888")?
    .run()
    .await
}
