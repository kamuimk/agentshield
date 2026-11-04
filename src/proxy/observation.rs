//! Conservative response framing observations, never remote application receipts.
//! Only bounded headers are buffered; response content is counted and discarded.
enum Chunk {
    Size(Vec<u8>),
    Data(u64),
    Crlf(usize),
    Final(usize),
}

#[derive(Default)]
pub(crate) struct TransportObservation {
    attempted: bool,
    headers: Vec<u8>,
    status: Option<u16>,
    remaining: Option<u64>,
    close_delimited: bool,
    complete: bool,
    invalid: bool,
    head: bool,
    failed: bool,
    chunk: Option<Chunk>,
}
impl TransportObservation {
    pub(crate) fn new(method: &str) -> Self {
        Self {
            head: method == "HEAD",
            ..Self::default()
        }
    }
    pub(crate) fn failure(&mut self) {
        self.failed = true;
    }
    pub(crate) fn attempt(&mut self) {
        self.attempted = true;
    }
    pub(crate) fn feed(&mut self, mut bytes: &[u8]) {
        if self.invalid {
            return;
        }
        if self.complete {
            if !bytes.is_empty() {
                self.complete = false;
                self.invalid = true;
            }
            return;
        }
        if self.status.is_none() {
            // Buffer one header byte at a time, so a large body in the same read
            // cannot be retained or make bounded headers appear oversized.
            while !bytes.is_empty() && self.status.is_none() && !self.invalid {
                self.headers.push(bytes[0]);
                bytes = &bytes[1..];
                if self.headers.len() > 32768 {
                    self.invalid = true;
                    self.headers.clear();
                    return;
                }
                if self.headers.ends_with(b"\r\n\r\n") {
                    let mut fields = [httparse::EMPTY_HEADER; 128];
                    let mut response = httparse::Response::new(&mut fields);
                    let Ok(httparse::Status::Complete(_)) = response.parse(&self.headers) else {
                        self.invalid = true;
                        self.headers.clear();
                        return;
                    };
                    let Some(status) = response.code.filter(|s| (100..=599).contains(s)) else {
                        self.invalid = true;
                        self.headers.clear();
                        return;
                    };
                    if (100..200).contains(&status) && status != 101 {
                        self.headers.clear();
                        continue;
                    }
                    self.status = Some(status);
                    let lengths: Vec<_> = response
                        .headers
                        .iter()
                        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
                        .collect();
                    let encodings: Vec<_> = response
                        .headers
                        .iter()
                        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
                        .collect();
                    if lengths.len() > 1
                        || encodings.len() > 1
                        || (!lengths.is_empty() && !encodings.is_empty())
                        || status == 101
                    {
                        self.invalid = true;
                    } else if self.head || status == 204 || status == 304 {
                        self.remaining = Some(0);
                        self.complete = true;
                    } else if !encodings.is_empty() {
                        if encodings[0].value.eq_ignore_ascii_case(b"chunked") {
                            self.chunk = Some(Chunk::Size(Vec::new()));
                        } else {
                            self.invalid = true;
                        }
                    } else if let Some(length) = lengths.first() {
                        match std::str::from_utf8(length.value)
                            .ok()
                            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            Some(n) => {
                                self.remaining = Some(n);
                                self.complete = n == 0;
                            }
                            None => self.invalid = true,
                        }
                    } else {
                        self.close_delimited = true;
                    }
                    self.headers.clear();
                }
            }
        }
        if self.invalid {
            return;
        }
        if self.chunk.is_some() {
            for &byte in bytes {
                if self.complete {
                    self.complete = false;
                    self.invalid = true;
                    break;
                }
                let next = match self.chunk.take().expect("chunk state") {
                    Chunk::Size(mut line) => {
                        line.push(byte);
                        if line.len() > 512 {
                            self.invalid = true;
                            None
                        } else if line.ends_with(b"\r\n") {
                            match httparse::parse_chunk_size(&line) {
                                Ok(httparse::Status::Complete((used, n))) if used == line.len() => {
                                    Some(if n == 0 {
                                        Chunk::Final(0)
                                    } else {
                                        Chunk::Data(n)
                                    })
                                }
                                _ => {
                                    self.invalid = true;
                                    None
                                }
                            }
                        } else {
                            Some(Chunk::Size(line))
                        }
                    }
                    Chunk::Data(n) => Some(if n == 1 {
                        Chunk::Crlf(0)
                    } else {
                        Chunk::Data(n - 1)
                    }),
                    Chunk::Crlf(pos) => {
                        if byte != b"\r\n"[pos] {
                            self.invalid = true;
                            None
                        } else {
                            Some(if pos == 0 {
                                Chunk::Crlf(1)
                            } else {
                                Chunk::Size(Vec::new())
                            })
                        }
                    }
                    Chunk::Final(pos) => {
                        // Unknown trailers are deliberately not certified.
                        if byte != b"\r\n"[pos] {
                            self.invalid = true;
                            None
                        } else if pos == 0 {
                            Some(Chunk::Final(1))
                        } else {
                            self.complete = true;
                            Some(Chunk::Final(2))
                        }
                    }
                };
                self.chunk = next;
                if self.invalid {
                    break;
                }
            }
            return;
        }
        if let Some(remaining) = self.remaining {
            if bytes.len() as u64 > remaining {
                self.complete = false;
                self.invalid = true;
                return;
            }
            self.remaining = Some(remaining - bytes.len() as u64);
            self.complete = self.remaining == Some(0);
        }
    }
    pub(crate) fn eof(&mut self) {
        if !self.invalid && self.status.is_some() && self.close_delimited {
            self.complete = true;
        }
    }
    pub(crate) fn value(&self) -> serde_json::Value {
        let phase = if self.complete && !self.invalid {
            "response_complete"
        } else if self.status.is_some() {
            "response_headers"
        } else if self.attempted {
            "attempted_unknown"
        } else {
            "not_attempted"
        };
        serde_json::json!({"phase":phase,"termination":if phase=="response_complete" && !self.failed {"completed"} else {"failed"},"httpStatus":self.status})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_writes_and_truncated_response_are_never_delivery_receipts() {
        let mut x = TransportObservation::new("POST");
        assert_eq!(x.value()["phase"], "not_attempted");
        x.attempt();
        assert_eq!(x.value()["phase"], "attempted_unknown");
        x.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc");
        x.eof();
        assert_eq!(x.value()["phase"], "response_headers");
        x.feed(b"d");
        assert_eq!(x.value()["phase"], "response_complete");
        x.feed(b"extra");
        assert_eq!(x.value()["phase"], "response_headers");
    }
    #[test]
    fn fragmented_headers_interim_and_connection_close() {
        let bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\n\r\nbody";
        let mut x = TransportObservation::new("POST");
        x.attempt();
        for byte in bytes {
            x.feed(&[*byte]);
        }
        assert_eq!(x.value()["phase"], "response_headers");
        x.eof();
        assert_eq!(x.value()["phase"], "response_complete");
        assert_eq!(x.value()["httpStatus"], 201);
    }
    #[test]
    fn chunk_boundaries_require_the_exact_terminal_frame() {
        let prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut x = TransportObservation::new("POST");
        x.attempt();
        x.feed(prefix);
        for b in b"3\r\nabc\r\n0\r\n\r\n" {
            x.feed(&[*b]);
        }
        assert_eq!(x.value()["phase"], "response_complete");
        for body in [
            b"3\r\nabc\r\n0\r\n".as_slice(),
            b"3\r\nab",
            b"3\r\nabcXX0\r\n\r\n",
            b"0\r\nTrailer: value\r\n\r\n",
            b"0\r\n\r\nextra",
        ] {
            let mut x = TransportObservation::new("POST");
            x.attempt();
            x.feed(prefix);
            x.feed(body);
            x.eof();
            assert_ne!(x.value()["phase"], "response_complete");
        }
    }

    #[test]
    fn malformed_ambiguous_and_unqualified_framing_remain_unknown() {
        for h in [
            "Content-Length: 0\r\nContent-Length: 0",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
            "Content-Length: -1",
            "Transfer-Encoding: chunked",
        ] {
            let mut x = TransportObservation::new("POST");
            x.attempt();
            x.feed(format!("HTTP/1.1 200 OK\r\n{h}\r\n\r\n").as_bytes());
            x.eof();
            assert_ne!(x.value()["phase"], "response_complete");
        }
        let mut x = TransportObservation::new("POST");
        x.attempt();
        x.feed(&vec![b'a'; 40000]);
        assert!(x.headers.is_empty());
        assert_eq!(x.value()["phase"], "attempted_unknown");
    }
}
