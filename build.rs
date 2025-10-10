use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

fn main() -> std::io::Result<()> {
    // Tell Cargo to re-run this script if `build.rs` or `sizes.txt` changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=sizes.txt");

    let consts_path = Path::new("sizes.txt");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let dest_path = Path::new(&out_dir).join("generated_sizes.rs");

    let input_file = fs::File::open(consts_path)?;
    let mut output_file = fs::File::create(dest_path)?;

    // Process the input file line by line
    for line in BufReader::new(input_file).lines() {
        let line = line?;

        // Remove comments startring with `#` and trim whitespace
        let line_without_comment = line.split('#').next().unwrap_or("").trim();
        if line_without_comment.is_empty() {
            continue;
        }

        // Parse the constant itself (`u64` for architecture independence)
        match line_without_comment.parse::<u64>() {
            Ok(num) => {
                // Convert the number to its binary string representation
                let binary_string = format!("{:b}", num);

                // Format the binary string into a comma-separated list for the `bs!` macro
                let bs_args = binary_string
                    .chars()
                    .map(|c| c.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");

                let code_line = format!("impl_const!(unsafe {}, bs!({}));\n", num, bs_args);
                write!(output_file, "{}", code_line)?;
            }
            Err(_) => {
                // If anything fails, panic definitively and the user can work it out
                panic!(
                    "Failed to parse '{}' as a number in sizes.txt",
                    line_without_comment
                );
            }
        }
    }

    Ok(())
}
