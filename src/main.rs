#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use std::io::{self, Write};
use std::process;
use registry::*;
use clearscreen::*;
use utfx::U16CString;

const __subhives: &'static [&'static str] = &[
    "< HKEY_CLASSES_ROOT : HKCR >",
    "< HKEY_CURRENT_USER : HKCU >",
    "< HKEY_LOCAL_MACHINE : HKLM >",
    "< HKEY_USERS : HKU >",
    "< HKEY_CURRENT_CONFIG : HKCC >"
];

const __subcmds: &'static [&'static str] = &[
    "< clear : [NO_PARAMS (CLEARS CONSOLE)] >",
    "< cls : [NO_PARAMS (CLEARS CONSOLE)] >",
    "< getcwd : [NO_PARAMS (DISPLAYS CURRENT WORKING DIRECTORY)] >",
    "< exit : [NO_PARAMS (EXITS SOFTWARE <> CODE '0')] >",
    "< ex : [NO_PARAMS (EXITS SOFTWARE <> CODE '0')] >",
    "< help : [NO_PARAMS (DISPLAYS ALL COMMANDS)] >",
    "< getchive : [NO_PARAMS (DISPLAYS CURRENT REGISTRY HIVE)] >",
    "< ls : [-a || -k || -v (DISPLAYS <ALL> || <KEYS> || <VALS> OF CURRENT WORKING DIRECTORY)] >",
    "< dir : [-a || -k || -v (DISPLAYS <ALL> || <KEYS> || <VALS> OF CURRENT WORKING DIRECTORY)] >",
    "< cd : [HKEY_NAME (CHANGES CURRENT DIRECTORY TO 'HKEY_NAME')] >",
    "< setchive : [HIVE_NAME (CHANGES CURRENT HIVE TO 'HIVE_NAME')] >",
    "< gethives : [NO_PARAMS (DISPLAYS ALL VARIANTS OF HIVE_NAME)] >",
    "< mk_key : [HKEY_NAME (CREATES A NEW KEY IN CURRENT DIRECTORY)] >",
    "< del_key : [HKEY_NAME (DELETES AN **EMPTY** EXISTING KEY IN CURRENT DIRECTORY)] <> '-o' TO OVERRIDE **EMPTY** >",
    "< mk_val : [VAL_NAME :: -b || -s || -ms || -es || -u32 || -u64 (CREATES A NEW VALUE WITH TYPE <BINARY> || <STRING> || <MULTI_STRING> || <EXP_STRING> || <DWORD> || <QWORD> IN CURRENT DIRECTORY)] >",
    "< del_val : [VAL_NAME (DELETES AN EXISTING VALUE IN CURRENT DIRECTORY)] >",
    "< edit_val : [VAL_NAME :: VAL_TYPE :: VAL_DATA (EDITS EXISTING VALUE IN CURRENT DIRECTORY)] >"
];

fn __subclr() {
    clear();

    println!("<> SGT-REGEDIT-RUST :: PLEASE RUN [help] FOR A LIST OF COMMANDS <>\n");
}

fn __subrun_cmd(__subcmd: &str, __subcrk: RegKey, __subchive: Hive, __subchive_dir: String) -> (RegKey, Hive, String) {
    let mut __subargs = __subcmd.split_whitespace();
    let __subarg_cmd = __subargs.next().unwrap().to_lowercase();
    let mut __subargs_lst: Vec<&str> = Vec::new();

    let mut __subn_crk = __subcrk;
    let mut __subn_chive = __subchive;
    let mut __subn_chive_dir = __subchive_dir;

    for __subarg in __subargs {
        __subargs_lst.push(__subarg);
    }

    match (__subarg_cmd.trim_end()) {
        "clear" => {
            __subclr();
        },
        "cls" => {
            __subclr();
        },
        "getcwd" => {
            println!("< CURRENT REGISTRY DIRECTORY : {} >\n", __subn_crk.to_string());
        },
        "exit" => {
            clear();

            process::exit(0);
        },
        "ex" => {
            clear();

            process::exit(0);
        },
        "help" => {
            println!("\n< LIST OF AVAILABLE COMMANDS >");

            for (__subcmd_str) in __subcmds.iter() {
                println!("{}", __subcmd_str);
            }

            println!();
        },
        "getchive" => {
            println!("< CURRENT REGISTRY HIVE : {} >\n", __subchive);
        },
        "setchive" => {
            let mut __subarg = String::new();

            if (__subargs_lst.len() >= 1) {
                __subarg = String::from(__subargs_lst[0]);
            }

            match (__subarg.trim_end()) {
                "hkc" | "hkey_classes_root" => {
                    __subn_chive = Hive::ClassesRoot;
                    __subn_chive_dir = String::new();
                    __subn_crk = Hive::ClassesRoot.open(__subn_chive_dir.as_str(), Security::Read).ok().unwrap();

                    println!("< SUCCESS <> SET REGISTRY HIVE TO HKEY_CLASSES_ROOT >\n");
                },
                "hkcu" | "hkey_current_user" => {
                    __subn_chive = Hive::CurrentUser;
                    __subn_chive_dir = String::new();
                    __subn_crk = Hive::CurrentUser.open(__subn_chive_dir.as_str(), Security::Read).ok().unwrap();

                    println!("< SUCCESS <> SET REGISTRY HIVE TO HKEY_CURRENT_USER >\n");
                },
                "hklm" | "hkey_local_machine" => {
                    __subn_chive = Hive::LocalMachine;
                    __subn_chive_dir = String::new();
                    __subn_crk = Hive::LocalMachine.open(__subn_chive_dir.as_str(), Security::Read).ok().unwrap();

                    println!("< SUCCESS <> SET REGISTRY HIVE TO HKEY_LOCAL_MACHINE >\n");
                },
                "hku" | "hkey_users" => {
                    __subn_chive = Hive::Users;
                    __subn_chive_dir = String::new();
                    __subn_crk = Hive::Users.open(__subn_chive_dir.as_str(), Security::Read).ok().unwrap();

                    println!("< SUCCESS <> SET REGISTRY HIVE TO HKEY_USERS >\n");
                },
                "hkcc" | "hkey_current_config" => {
                    __subn_chive = Hive::CurrentConfig;
                    __subn_chive_dir = String::new();
                    __subn_crk = Hive::CurrentConfig.open(__subn_chive_dir.as_str(), Security::Read).ok().unwrap();

                    println!("< SUCCESS <> SET REGISTRY HIVE TO HKEY_CURRENT_CONFIG >\n");
                },
                _ => {
                    println!("< ERROR <> INVALID HIVE TYPE PARSED >\n");
                }
            }
        },
        "gethives" => {
            println!("\n< LIST OF AVAILABLE REGISTRY HIVES >");

            for (__subidx, __subhive_str) in __subhives.iter().enumerate() {
                println!("{}", __subhive_str);
            }

            println!();
        },
        "ls" => {
            let mut __subarg = String::new();

            if (__subargs_lst.len() == 0) {
                __subarg = String::from("-a");
            } else {
                __subarg = String::from(__subargs_lst[0]);
            }

            let __subdisp_keys = || {
                println!("\n< LIST OF KEYS IN REGISTRY DIRECTORY >");

                let mut __subfnd = false;

                for __subkey in __subn_crk.keys() {
                    println!("< {} >", __subkey.unwrap().to_string());

                    __subfnd = true;
                }

                if (!(__subfnd)) {
                    println!("< NO KEYS FOUND IN REGISTRY DIRECTORY >");
                }

                println!();
            };

            let __subdisp_vals = || {
                println!("\n< LIST OF VALUES IN REGISTRY DIRECTORY >");

                let mut __subfnd = false;

                for (__subidx, __subval) in __subn_crk.values().enumerate() {
                    println!("< {} :: {} >", __subval.as_ref().unwrap().name().to_string().ok().unwrap(), __subval.as_ref().unwrap().data().to_string());

                    __subfnd = true;
                }

                if (!(__subfnd)) {
                    println!("< NO VALUES FOUND IN REGISTRY DIRECTORY >");
                }

                println!();
            };

            match (__subarg.trim_end()) {
                "-a" => {
                    __subdisp_keys();
                    __subdisp_vals();
                },
                "-k" => {
                    __subdisp_keys();
                },
                "-v" => {
                    __subdisp_vals();
                },
                _ => {
                    println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
                }
            };
        },
        "dir" => {
            let mut __subarg = String::new();

            if (__subargs_lst.len() == 0) {
                __subarg = String::from("-a");
            } else {
                __subarg = String::from(__subargs_lst[0]);
            }

            let __subdisp_keys = || {
                println!("\n< LIST OF KEYS IN REGISTRY DIRECTORY >");

                let mut __subfnd = false;

                for __subkey in __subn_crk.keys() {
                    println!("< {} >", __subkey.unwrap().to_string());

                    __subfnd = true;
                }

                if (!(__subfnd)) {
                    println!("< NO KEYS FOUND IN REGISTRY DIRECTORY >");
                }

                println!();
            };

            let __subdisp_vals = || {
                println!("\n< LIST OF VALUES IN REGISTRY DIRECTORY >");

                let mut __subfnd = false;

                for (__subidx, __subval) in __subn_crk.values().enumerate() {
                    println!("< {} :: {} >", __subval.as_ref().unwrap().name().to_string_lossy(), __subval.as_ref().unwrap().data().to_string());

                    __subfnd = true;
                }

                if (!(__subfnd)) {
                    println!("< NO VALUES FOUND IN REGISTRY DIRECTORY >");
                }

                println!();
            };

            match (__subarg.trim_end()) {
                "-a" => {
                    __subdisp_keys();
                    __subdisp_vals();
                },
                "-k" => {
                    __subdisp_keys();
                },
                "-v" => {
                    __subdisp_vals();
                },
                _ => {
                    println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
                }
            };
        },
        "cd" => {
            let mut __subarg = String::new();

            if (__subargs_lst.len() >= 1) {
                for (__substr) in __subargs_lst {
                    __subarg.insert_str(__subarg.len(), String::from(format!("{} ", __substr)).as_str());
                }

                __subarg.pop();
                __subarg.insert_str(__subarg.len(), "\\");
                __subarg = __subarg.to_uppercase();
                __subarg = String::from(__subarg.trim_end_matches("\\"));
                __subarg = String::from(__subarg.trim_start_matches("\\"));

                if (!(__subarg.trim_end() == "/") && !(__subarg.contains("../"))) {
                    if (!(__subn_chive_dir.is_empty())) {
                        __subarg.insert(0, '\\');
                    }
                }
            }

            if (!(__subarg.contains(':')) && !(__subarg.trim_end() == "/") && !(__subarg.contains("../")) && !(__subarg.trim_end() == "\\")) {
                let __substr_path = String::from(format!("{}{}", __subn_chive_dir, __subarg));
                let __subn_hndl = __subchive.open(__substr_path, Security::Read);

                match (__subn_hndl) {
                    Ok(Chive) => {
                        __subn_chive_dir.insert_str(__subn_chive_dir.len(), __subarg.as_str());

                        println!("< SUCCESS <> SET REGISTRY DIRECTORY TO {} >\n", __subn_chive_dir);
                    },
                    Err(ChiveError) => match (ChiveError) {
                        NotFound => {
                            println!("< ERROR <> INVALID REGISTRY DIRECTORY >\n");
                        },
                        PermissionDenied => {
                            println!("< ERROR <> ACCESS DENIED TO REGISTRY DIRECTORY >\n");
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO ACCESS REGISTRY DIRECTORY >\n");
                        }
                    }
                };
            } else if (__subarg.trim_end() == "/") {
                __subn_chive_dir = String::new();
            } else if (__subarg.contains("../")) {
                let mut __subarg_occ = __subarg.matches("../").count();
                let mut __subchive_dir_occ = __subn_chive_dir.matches("\\").count() + 1;
                let mut __subidx = 0;

                if (__subarg_occ >= __subchive_dir_occ) {
                    __subarg_occ = __subchive_dir_occ.clone();

                    __subn_chive_dir = String::new();
                } else {
                    let mut __subn_dir = __subn_chive_dir.clone().chars().rev().collect::<String>();

                    for (__subi) in (0..__subarg_occ) {
                        let mut __subidx: usize = __subn_dir.find("\\").unwrap();
                        __subidx += 1;

                        __subn_dir.replace_range(..__subidx, "");
                    }

                    __subn_dir = __subn_dir.chars().rev().collect::<String>();

                    __subn_chive_dir = __subn_dir;
                }
            } else {
                println!("< ERROR <> INVALID REGISTRY DIRECTORY >\n");
            }
        },
        "mk_key" => {
            let mut __subkey_nm = String::new();
            let mut __subkey_pth = String::new();

            if (__subargs_lst.len() >= 1) {
                __subkey_nm = String::from(__subargs_lst[0]);
                __subkey_pth = String::from(format!("{}\\{}", __subn_chive_dir, __subkey_nm));
            }

            if (!(__subkey_nm.is_empty()) && !(__subkey_pth.is_empty())) {
                let __subchk_pth_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::CreateSubKey);

                match (&__subchk_pth_hndl) {
                    Ok(Chive) => {

                        let __subchk_key_hndl = __subchive.open(__subkey_pth.clone().as_str(), Security::Read);

                        match (&__subchk_key_hndl) {
                            Ok(CNHive) => {
                                println!("< ERROR <> SUBKEY ALREADY EXISTS IN DIRECTORY >\n");
                            },
                            Err(CNHiveError) => match (CNHiveError) {
                                NotFound => {
                                    let __subcrt_key_hndl = __subchive.create(__subkey_pth.clone().as_str(), Security::CreateSubKey);

                                    match (&__subcrt_key_hndl) {
                                        Ok(CNNHive) => {
                                            println!("< SUCCESS <> SUBKEY '{}' SUCCESSFULLY CREATED >\n", __subkey_nm);
                                        },
                                        Err(CNNHiveError) => match (CNNHiveError) {
                                            PermissionDenied => {
                                                println!("< ERROR <> INSUFFICIENT PERMISSIONS TO CREATE SUBKEY IN DIRECTORY >\n");
                                            },
                                            _ => {}
                                        }
                                    }
                                },
                                PermissionDenied => {
                                    println!("< ERROR <> INSUFFICIENT PERMISSIONS TO CREATE SUBKEY IN DIRECTORY >\n");
                                },
                                _ => {
                                    println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO CREATE SUBKEY IN DIRECTORY >\n");
                                }
                            }
                        };
                    },
                    Err(ChiveError) => match (ChiveError) {
                        PermissionDenied => {
                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO CREATE SUBKEY IN DIRECTORY >\n");
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO CREATE SUBKEY IN DIRECTORY >\n");
                        }
                    }
                };
            } else {
                println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
            }
        },
        "del_key" => {
            let mut __subkey_nm = String::new();
            let mut __subkey_pth = String::new();
            let mut __subovr = false;

            if (__subargs_lst.len() >= 1) {
                __subkey_nm = String::from(__subargs_lst[0]);
                __subkey_pth = String::from(format!("{}\\{}", __subn_chive_dir, __subkey_nm));

                if (__subargs_lst.len() >= 2) {
                    if (__subargs_lst[1].trim_end() == "-o") {
                        __subovr = true;

                        println!("true");
                    }
                }
            }

            if (!(__subkey_nm.is_empty()) && !(__subkey_pth.is_empty())) {
                let __subchk_pth_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::Write);

                match (&__subchk_pth_hndl) {
                    Ok(Chive) => {

                        let __subchk_key_hndl = __subchive.open(__subkey_pth.clone().as_str(), Security::Write);

                        match (&__subchk_key_hndl) {
                            Ok(CNHive) => {
                                let __subdel_key_hndl = __subchk_key_hndl.unwrap().delete_self(__subovr);

                                match (&__subdel_key_hndl) {
                                    Ok(CNNHive) => {
                                        println!("< SUCCESS <> SUBKEY '{}' SUCCESSFULLY DELETED >\n", __subkey_nm);
                                    },
                                    Err(CNNHiveError) => match(CNNHiveError) {
                                        PermissionDenied => {
                                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO DELETE SUBKEY FROM DIRECTORY (LAST) >\n");
                                        },
                                        _ => {
                                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO DELETE SUBKEY FROM DIRECTORY >\n");
                                        }
                                    }
                                };
                            },
                            Err(CNHiveError) => match (CNHiveError) {
                                NotFound => {
                                    println!("< ERROR <> SUBKEY '{}' NOT FOUND IN DIRECTORY >\n", __subkey_nm);
                                },
                                PermissionDenied => {
                                    println!("< ERROR <> INSUFFICIENT PERMISSIONS TO DELETE SUBKEY FROM DIRECTORY (SECOND) >\n");
                                },
                                _ => {
                                    println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO DELETE SUBKEY FROM DIRECTORY >\n");
                                }
                            }
                        };
                    },
                    Err(ChiveError) => match (ChiveError) {
                        PermissionDenied => {
                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO DELETE SUBKEY FROM DIRECTORY (FIRST) >\n");
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO DELETE SUBKEY FROM DIRECTORY >\n");
                        }
                    }
                };
            } else {
                println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
            }
        },
        "mk_val" => {
            let mut __subval_nm = String::new();
            let mut __subval_data_typ = String::new();
            let mut __subval_data = String::new();

            let __subdata_typs = [
                "-b",
                "-s",
                "-ms",
                "-es",
                "-u32",
                "-u64"
            ];

            if (__subargs_lst.len() >= 2) {
                __subval_nm = String::from(__subargs_lst[0]);
                __subval_data_typ = String::from(__subargs_lst[1]);

                if (__subargs_lst.len() >= 3) {
                    __subval_data = String::from(__subargs_lst[2]);
                }
            }

            if (!__subval_nm.is_empty() && !__subval_data_typ.is_empty() && __subdata_typs.contains(&__subval_data_typ.as_str())) {
                let __subchk_pth_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::SetValue);

                match (&__subchk_pth_hndl) {
                    Ok(Chive) => {
                        let __subchk_vals_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::Read);
                        let mut __subval_fnd = false;

                        for (__subval) in (__subchk_vals_hndl.unwrap().values()) {
                            match (__subval) {
                                Ok(ValRef) => {
                                    if (ValRef.name().to_string_lossy().to_uppercase() == __subval_nm.clone().to_uppercase()) {
                                        __subval_fnd = true;
                                    }
                                },
                                Err(ValError) => ()
                            }
                        }
                        
                        if (!__subval_fnd) {
                            let mut __subdata = Data::None;

                            if (__subval_data_typ == "-b") {
                                if (!(__subval_data.is_empty())) {
                                    let mut __subbin_vec: Vec<u8> = Vec::new();

                                    if (__subval_data.starts_with("0x")) {
                                        __subval_data = String::from(__subval_data.trim_start_matches("0x"));
                                    }

                                    for __subbin_dig in __subval_data.chars() {
                                        if (__subbin_dig == '1' || __subbin_dig == '0') {
                                            __subbin_vec.push(__subbin_dig.to_digit(10).unwrap() as u8);
                                        }
                                    }

                                    __subdata = Data::Binary(__subbin_vec);
                                } else {
                                    __subdata = Data::Binary(vec![]);
                                }
                            } else if (__subval_data_typ == "-s") {
                                if (!(__subval_data.is_empty())) {
                                    __subdata = Data::String(U16CString::from_str(String::from(__subval_data).as_str()).unwrap());
                                } else {
                                    __subdata = Data::String(U16CString::from_str(String::new()).unwrap());
                                }
                            } else if (__subval_data_typ == "-ms") {
                                if (!(__subval_data.is_empty())) {
                                    let mut __substr_vec: Vec<U16CString> = vec![];
                                    let mut __substr = String::new();

                                    for __subchar in __subval_data.chars() {
                                        if (__subchar != '\n') {
                                            __substr.push(__subchar);
                                        } else {
                                            __substr_vec.push(U16CString::from_str(String::from(&__substr)).unwrap());
                                            __substr = String::new();
                                        }
                                    }

                                    __subdata = Data::MultiString(__substr_vec);
                                } else {
                                    __subdata = Data::MultiString(vec![]);
                                }
                            } else if (__subval_data_typ == "-es") {
                                if (!(__subval_data.is_empty())) {
                                    __subdata = Data::ExpandString(U16CString::from_str(String::from(__subval_data)).unwrap());
                                } else {
                                    __subdata = Data::ExpandString(U16CString::from_str(String::new()).unwrap());
                                }
                            } else if (__subval_data_typ == "-u32") {
                                if (!(__subval_data.is_empty())) {
                                    let mut __subu32: u32 = 0;

                                    match (__subval_data.parse::<u32>()) {
                                        Ok(Num) => {
                                            __subu32 = Num;

                                            __subdata = Data::U32(__subu32);
                                        },
                                        Err(NumErr) => {
                                            __subdata = Data::U32(u32::MAX);
                                        }
                                    };
                                } else {
                                    __subdata = Data::U32(u32::MAX);
                                }
                            } else if (__subval_data_typ == "-u64") {
                                if (!(__subval_data.is_empty())) {
                                    let mut __subu64: u64 = 0;

                                    match (__subval_data.parse::<u64>()) {
                                        Ok(Num) => {
                                            __subu64 = Num;

                                            __subdata = Data::U64(__subu64);
                                        },
                                        Err(NumErr) => {
                                            __subdata = Data::U64(u64::MAX);
                                        }
                                    };
                                } else {
                                    __subdata = Data::U64(u64::MAX);
                                }
                            }
                            
                            let __subcrt_val_hndl = __subchk_pth_hndl.unwrap().set_value(__subval_nm.clone().as_str(), &__subdata);

                            match (&__subcrt_val_hndl) {
                                Ok(CNHive) => {
                                    println!("< SUCCESS <> VALUE '{}' SUCCESSFULLY CREATED IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                },
                                Err(CNHiveError) => match (CNHiveError) {
                                    PermissionDenied => {
                                        println!("< ERROR <> INSUFFICIENT PERMISSIONS TO CREATE VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    },
                                    _ => {
                                        println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO CREATE VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    }
                                }
                            };
                        } else {
                            println!("< ERROR <> VALUE '{}' ALREADY EXISTS IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    },
                    Err(ChiveError) => match (ChiveError) {
                        PermissionDenied => {
                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO CREATE VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO CREATE VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    }
                };
            } else {
                println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
            }
        },
        "del_val" => {
            let mut __subval_nm = String::new();

            if (__subargs_lst.len() >= 1) {
                __subval_nm = String::from(__subargs_lst[0]);
            }

            if (!__subval_nm.is_empty()) {
                let __subchk_pth_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::SetValue);

                match (&__subchk_pth_hndl) {
                    Ok(Chive) => {
                        let __subchk_vals_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::Read);
                        let mut __subval_fnd = false;

                        for (__subval) in (__subchk_vals_hndl.unwrap().values()) {
                            match (__subval) {
                                Ok(ValRef) => {
                                    if (ValRef.name().to_string_lossy().to_uppercase() == __subval_nm.clone().to_uppercase()) {
                                        __subval_fnd = true;
                                    }
                                },
                                Err(ValError) => ()
                            }
                        }
                        
                        if (__subval_fnd) {
                            let __subdel_val_hndl = __subchk_pth_hndl.unwrap().delete_value(__subval_nm.clone().as_str());

                            match (&__subdel_val_hndl) {
                                Ok(CNHive) => {
                                    println!("< SUCCESS <> VALUE '{}' SUCCESSFULLY DELETED FROM REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                },
                                Err(CNHiveError) => match (CNHiveError) {
                                    PermissionDenied => {
                                        println!("< ERROR <> INSUFFICIENT PERMISSIONS TO DELETE VALUE '{}' FROM REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    },
                                    _ => {
                                        println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO DELETE VALUE '{}' FROM REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    }
                                }
                            };
                        } else {
                            println!("< ERROR <> VALUE '{}' DOESN'T EXIST IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    },
                    Err(ChiveError) => match (ChiveError) {
                        PermissionDenied => {
                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO DELETE VALUE '{}' FROM REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO DELETE VALUE '{}' FROM REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    }
                };
            } else {
                println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
            }
        },
        "edit_val" => {
            let mut __subval_nm = String::new();
            let mut __subval_data_typ = String::new();
            let mut __subval_data = String::new();

            let __subdata_typs = [
                "-b",
                "-s",
                "-ms",
                "-es",
                "-u32",
                "-u64"
            ];

            if (__subargs_lst.len() >= 3) {
                __subval_nm = String::from(__subargs_lst[0]);
                __subval_data_typ = String::from(__subargs_lst[1]);
                __subval_data = String::from(__subargs_lst[2]);
            }

            if (!(__subval_nm.is_empty()) && !(__subval_data.is_empty()) && !(__subval_data_typ.is_empty()) && __subdata_typs.contains(&__subval_data_typ.as_str())) {
                let __subchk_pth_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::SetValue);

                match (&__subchk_pth_hndl) {
                    Ok(Chive) => {
                        let __subchk_vals_hndl = __subchive.open(__subn_chive_dir.clone().as_str(), Security::Read);
                        let mut __subval_fnd = false;

                        for (__subval) in (__subchk_vals_hndl.unwrap().values()) {
                            match (__subval) {
                                Ok(ValRef) => {
                                    if (ValRef.name().to_string_lossy().to_uppercase() == __subval_nm.clone().to_uppercase()) {
                                        __subval_fnd = true;
                                    }
                                },
                                Err(ValError) => ()
                            }
                        }
                        
                        if (__subval_fnd) {
                            let mut __subdata = Data::None;

                            if (__subval_data_typ == "-b") {
                                let mut __subbin_vec: Vec<u8> = Vec::new();

                                if (__subval_data.starts_with("0x")) {
                                    __subval_data = String::from(__subval_data.trim_start_matches("0x"));
                                }

                                for __subbin_dig in __subval_data.chars() {
                                    if (__subbin_dig == '1' || __subbin_dig == '0') {
                                        __subbin_vec.push(__subbin_dig.to_digit(10).unwrap() as u8);
                                    }
                                }

                                __subdata = Data::Binary(__subbin_vec);
                            } else if (__subval_data_typ == "-s") {
                                __subdata = Data::String(U16CString::from_str(String::from(__subval_data).as_str()).unwrap());
                            } else if (__subval_data_typ == "-ms") {
                                let mut __substr_vec: Vec<U16CString> = vec![];
                                let mut __substr = String::new();

                                for __subchar in __subval_data.chars() {
                                    if (__subchar != '\n') {
                                        __substr.push(__subchar);
                                    } else {
                                        __substr_vec.push(U16CString::from_str(String::from(&__substr)).unwrap());
                                        __substr = String::new();
                                    }
                                }

                                __subdata = Data::MultiString(__substr_vec);
                            } else if (__subval_data_typ == "-es") {
                                __subdata = Data::ExpandString(U16CString::from_str(String::from(__subval_data)).unwrap());
                            } else if (__subval_data_typ == "-u32") {
                                let mut __subu32: u32 = 0;

                                match (__subval_data.parse::<u32>()) {
                                    Ok(Num) => {
                                        __subu32 = Num;

                                        __subdata = Data::U32(__subu32);
                                    },
                                    Err(NumErr) => {
                                        __subdata = Data::None;
                                    }
                                };
                            } else if (__subval_data_typ == "-u64") {
                                let mut __subu64: u64 = 0;

                                match (__subval_data.parse::<u64>()) {
                                    Ok(Num) => {
                                        __subu64 = Num;

                                        __subdata = Data::U64(__subu64);
                                    },
                                    Err(NumErr) => {
                                        __subdata = Data::None;
                                    }
                                };
                            }
                            
                            let __subed_val_hndl = __subchk_pth_hndl.unwrap().set_value(__subval_nm.clone().as_str(), &__subdata);

                            match (&__subed_val_hndl) {
                                Ok(CNHive) => {
                                    println!("< SUCCESS <> VALUE '{}' SUCCESSFULLY CHANGED IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                },
                                Err(CNHiveError) => match (CNHiveError) {
                                    PermissionDenied => {
                                        println!("< ERROR <> INSUFFICIENT PERMISSIONS TO EDIT VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    },
                                    _ => {
                                        println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO EDIT VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                                    }
                                }
                            };
                        } else {
                            println!("< ERROR <> VALUE '{}' DOESN'T EXIST IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    },
                    Err(ChiveError) => match (ChiveError) {
                        PermissionDenied => {
                            println!("< ERROR <> INSUFFICIENT PERMISSIONS TO EDIT VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        },
                        _ => {
                            println!("< ERROR <> UNKNOWN ERROR WHILST ATTEMPTING TO EDIT VALUE '{}' IN REGISTRY KEY >\n", __subval_nm.clone().as_str());
                        }
                    }
                };
            } else {
                println!("< ERROR <> INVALID ARGUMENT(S) PARSED >\n");
            }
        },
        _ => {
            println!("< ERROR OCCURRED <> INVALID COMMAND : \"{}\" >\n", __subarg_cmd.trim_end());
        }
    };

    return (__subn_crk, __subn_chive, __subn_chive_dir);
}

fn main() {
    let __subq: bool = false;
    let mut __subchive: Hive = Hive::CurrentUser;
    let mut __subchive_dir: String = String::new();
    let mut __subcrk = __subchive.open(__subchive_dir.as_str(), Security::Read).ok();

    __subclr();

    while (!__subq) {
        let mut __subcmd: String = String::new();
        __subcrk = __subchive.open(__subchive_dir.as_str(), Security::Read).ok();

        print!("< {} > ", __subcrk.as_ref().unwrap().to_string());
        io::stdout().flush();

        io::stdin().read_line(&mut __subcmd);

        let __subret = __subrun_cmd(__subcmd.as_str(), __subcrk.unwrap(), __subchive, __subchive_dir);

        __subcrk = Some(__subret.0);
        __subchive = __subret.1;
        __subchive_dir = __subret.2;
    }
}
