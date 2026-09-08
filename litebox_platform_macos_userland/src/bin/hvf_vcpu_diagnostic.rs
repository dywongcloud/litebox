// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    match litebox_platform_macos_userland::hvf_vcpu_diagnostic_probe() {
        Ok(report) => println!("{report:#?}"),
        Err(error) => {
            eprintln!("HVF vCPU production diagnostic failed: {error}");
            std::process::exit(1);
        }
    }
}
