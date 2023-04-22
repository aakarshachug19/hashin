use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

fn handle_client(stream: TcpStream) {
    let mut reader = BufReader::new(&stream);
    let mut writer = stream.try_clone().expect("failed to clone stream");

    let mut line = String::new();
    while let Ok(_) = reader.read_line(&mut line) {
        // Process the client's request
        let result = match line.trim() {
            "simplebench" => simple_bench(&opts),
            "genpasswords" => gen_passwords(&opts),
            "hashesfromfile" => hashes_from_file(&opts),
            _ => Err("Unknown command".to_string()),
        };

        // Write the result back to the client
        match result {
            Ok(res) => {
                writer.write(res.as_bytes()).unwrap();
            }
            Err(err) => {
                writer.write(err.as_bytes()).unwrap();
            }
        }
        
        // Clear the line buffer
        line.clear();
    }
}
