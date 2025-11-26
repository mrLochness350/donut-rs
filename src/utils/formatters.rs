use std::fmt::Write;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use crate::errors::DonutResult;
use crate::types::enums::OutputFormat;

pub(crate) fn base64_template(pic: &[u8]) -> DonutResult<String> {
    let b64_data = BASE64_STANDARD.encode(pic);
    Ok(b64_data)
}

pub(crate) fn c_ruby_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let name = arr_name.unwrap_or("buf".to_string());
    if pic.is_empty() {
        return Ok(format!("unsigned char {name}[] = {{}};"));
    }
    let mut output = format!("unsigned char {name}[] = \n");
    for (i, byte) in pic.iter().enumerate() {
        if i % 16 == 0 {
            output.push('"');
        }
        output.push_str(&format!("\\x{byte:02x}"));

        if i % 16 == 15 || i + 1 == pic.len() {
            output.push_str("\"\n");
        }
    }
    output.push_str(";\n");
    Ok(output)
}


pub(crate) fn py_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let mut output = String::with_capacity(pic.len() * 4 + (pic.len() / 16 * 10));
    let name = arr_name.unwrap_or("buf".to_string());
    output.push_str(&format!("{name} = (\n"));
    for chunk in pic.chunks(16) {
        output.push_str("    b\"");
        for byte in chunk {
            write!(&mut output, "\\x{byte:02x}").unwrap();
        }
        output.push_str("\"\n");
    }
    output.push_str(")\n");
    Ok(output)
}

pub(crate) fn powershell_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let name = arr_name.unwrap_or("buf".to_string());
    let mut output = format!("[Byte[]] ${name} = " );
    let pic_len = pic.len();
    dotnet_template(pic, &mut output, pic_len);
    Ok(output)
}
pub(crate) fn csharp_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let name = arr_name.unwrap_or("buf".to_string());
    let mut output = format!("byte[] {name} = new byte[{}] {{\n", pic.len());
    let pic_len = pic.len();
    dotnet_template(pic, &mut output, pic_len);
    output.push_str("};");
    Ok(output)
}

fn dotnet_template(pic: &[u8], output: &mut String, pic_len: usize) {
    for (i, byte) in pic.iter().enumerate() {
        output.push_str(&format!("0x{byte:02x}"));
        if i < pic_len - 1 {
            output.push(',');
        }
        if i % 12 == 11 || i + 1 == pic.len() {
            output.push('\n');
            if i + 1 != pic.len() {
                output.push_str("  ");
            }
        }
    }
}

pub(crate) fn hex_template(pic: &[u8]) -> DonutResult<String> {
    let hex_str = hex::encode(pic);
    Ok(hex_str)
}

pub(crate) fn uuid_template(mut data: Vec<u8>) -> DonutResult<String> {
    let mut output = String::new();
    let rem = data.len() % 16;
    if rem != 0 {
        data.extend(std::iter::repeat_n(0, 16 - rem));
    }
    for chunk in data.chunks(16) {
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            chunk[3], chunk[2], chunk[1], chunk[0],
            chunk[5], chunk[4],
            chunk[7], chunk[6],
            chunk[8], chunk[9],
            chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15]
        );
        output.push_str(&uuid);
        output.push('\n');
    }
    Ok(output)
}

pub(crate) fn rust_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let name = arr_name.unwrap_or("SHELLCODE".to_string()).to_ascii_uppercase();
    let date = chrono::Local::now().format("%d\\%m\\%y").to_string();
    let comment = format!("/// Compiled via libdonut-rs on {date}");
    use std::fmt::Write;
    if pic.is_empty() {
        return Ok(format!("{comment}\npub static {name}: [u8; 0] = &[];"));
    }
    let mut output = format!("{comment}\npub static {name}: [u8; {}] = [\n", pic.len());
    for (i, byte) in pic.iter().enumerate() {
        if i % 12 == 0 {
            output.push_str("    ");
        }
        write!(output, "0x{byte:02x}, ").unwrap();
        if i % 12 == 11 || i + 1 == pic.len() {
            output.push('\n');
        }
    }

    output.push_str("];\n");
    Ok(output)
}

pub(crate) fn raw_template(pic: &[u8]) -> DonutResult<String> {
    use std::fmt::Write;
    let mut output = String::new();
    for byte in pic {
        write!(output, "\\x{byte:02x}").unwrap();
    }
    Ok(output)
}



pub(crate) fn golang_template(pic: &[u8], arr_name: Option<String>) -> DonutResult<String> {
    let name = arr_name.unwrap_or("payload".to_string());
    use std::fmt::Write;
    if pic.is_empty() {
        return Ok(format!("var {name} = []byte{{}}"));
    }

    let mut output = String::from("var payload = []byte{\n");
    for (i, byte) in pic.iter().enumerate() {
        if i % 12 == 0 {
            output.push_str("    ");
        }
        write!(output, "0x{byte:02x}, ").unwrap();
        if i % 12 == 11 || i + 1 == pic.len() {
            output.push('\n');
        }
    }
    output.push_str("}\n");
    Ok(output)
}


pub(crate) fn format_bytes(bytes: &[u8], format: OutputFormat, name: Option<String>) -> DonutResult<String> {
    let str = match format {
        OutputFormat::Ruby | OutputFormat::C => c_ruby_template(bytes, name)?,
        OutputFormat::CSharp => csharp_template(bytes, name)?,
        OutputFormat::Powershell => powershell_template(bytes, name)?,
        OutputFormat::Rust => rust_template(bytes, name)?,
        OutputFormat::Python => py_template(bytes, name)?,
        OutputFormat::Raw => raw_template(bytes)?,
        OutputFormat::Hex => hex_template(bytes)?,
        OutputFormat::Uuid => uuid_template(bytes.to_vec())?,
        OutputFormat::Base64 => base64_template(bytes)?,
        OutputFormat::Golang => golang_template(bytes, name)?
    };
    Ok(str)
}