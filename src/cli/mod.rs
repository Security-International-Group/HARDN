/*use clap::{App, Arg};

// mod.rs - CLI module 

pub mod args;  // Declare submodule for argument parsing


pub fn run() {
    let matches = App::new("HARDN")
        .version("1.0")
        .author("Your Name")
        .about("Extended Detection and Response Tool")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .value_name("FILE")
            .help("Sets the input file")
            .takes_value(true))
        .get_matches();

    if let Some(input) = matches.value_of("input") {
        println!("Processing input: {}", input);
       
    }
}*/