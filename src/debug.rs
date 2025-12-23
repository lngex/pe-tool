use std::ffi::CStr;
use std::str::FromStr;
use std::time::Duration;
use pdb::{ModuleInfo, ProcedureSymbol};
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DEBUG_DIRECTORY, IMAGE_DEBUG_TYPE_CODEVIEW, IMAGE_SECTION_HEADER,
};
use windows_sys::core::GUID;
const CV_SIGNATURE_RSDS: &str = "RSDS";
const CV_SIGNATURE_NB10: &str = "01BN";
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub mod data {
    pub type IMAGE_NT_HEADERS = windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
}

#[cfg(target_arch = "x86")]
#[allow(non_camel_case_types)]
pub mod data {
    pub type IMAGE_NT_HEADERS = windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
}

use windows_sys::Win32::System::{
    Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_DEBUG,
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE},
};

use crate::debug::data::IMAGE_NT_HEADERS;
struct PdbInfo {
    pub age: u32,
    pub name: String,
    pub guid: String,
}

/// 解析debug信息
#[allow(dead_code, unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
pub unsafe fn pdb_info(pe: *const u8) -> Result<PdbInfo, String> {
    let dos_header = &*(pe as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return Err("当前文件不是PE文件".to_string());
    }
    let nt_header = &*(pe.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS);
    if nt_header.Signature != IMAGE_NT_SIGNATURE {
        return Err("当前文件不是PE文件".to_string());
    }
    // 获取节表
    let section_header = &*(pe
        .offset(dos_header.e_lfanew as isize)
        .add(size_of::<IMAGE_NT_HEADERS>())
        as *const IMAGE_SECTION_HEADER);
    // 节数
    let num_sections = nt_header.FileHeader.NumberOfSections;
    let index = IMAGE_DIRECTORY_ENTRY_DEBUG as usize;
    if let Some(debug_dir) = nt_header
        .OptionalHeader
        .DataDirectory
        .get(index)
        .filter(|debug_dir| debug_dir.VirtualAddress != 0 && debug_dir.Size != 0)
    {
        let file_offset = rva_to_offset(
            section_header as *const IMAGE_SECTION_HEADER,
            num_sections,
            debug_dir.VirtualAddress,
        );
        if file_offset.is_none() {
            return Err("在文件中找不到调试目录。".to_string());
        }
        // 计算调试目录项的数量
        let num_entries = debug_dir.Size / (size_of::<IMAGE_DEBUG_DIRECTORY>() as u32);
        let debug_directory_ptr = pe
            .add(file_offset.map(|of| of as usize).unwrap())
            .cast::<IMAGE_DEBUG_DIRECTORY>();
        for index in 0..num_entries {
            let debug_directory = &*debug_directory_ptr.add(index as usize);
            if debug_directory.Type == IMAGE_DEBUG_TYPE_CODEVIEW
                && debug_directory.PointerToRawData > 0
                && debug_directory.SizeOfData > 0
            {
                return if let Some(info) = parse_code_view_info(pe, debug_directory) {
                    Ok(info)
                } else {
                    Err("不支持当前PE版本".to_string())
                };
            }
        }
    }
    Err("找不到调试目录".to_string())
}

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
struct CV_INFO_PDB70 {
    pub CvSignature: u32,
    pub Signature: GUID,
    pub Age: u32,
    pub PdbFileName: [u8; 1],
}

impl CV_INFO_PDB70 {
    /// 获取DPB下载路径
    pub fn pdb_url(&self) -> String {
        let cpdb_name = unsafe { CStr::from_ptr(self.PdbFileName.as_ptr() as _) };
        let pdb_name = cpdb_name.to_str().unwrap();
        let guid = format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.Signature.data1,
            self.Signature.data2,
            self.Signature.data3,
            self.Signature.data4[0],
            self.Signature.data4[1],
            self.Signature.data4[2],
            self.Signature.data4[3],
            self.Signature.data4[4],
            self.Signature.data4[5],
            self.Signature.data4[6],
            self.Signature.data4[7],
        );
        format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
            pdb_name, guid, self.Age, pdb_name
        )
    }

    pub fn pdb_info(&self) -> PdbInfo {
        let cpdb_name = unsafe { CStr::from_ptr(self.PdbFileName.as_ptr() as _) };
        let pdb_name = cpdb_name.to_str().unwrap();
        let guid = format!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.Signature.data1,
            self.Signature.data2,
            self.Signature.data3,
            self.Signature.data4[0],
            self.Signature.data4[1],
            self.Signature.data4[2],
            self.Signature.data4[3],
            self.Signature.data4[4],
            self.Signature.data4[5],
            self.Signature.data4[6],
            self.Signature.data4[7],
        );
        PdbInfo {
            age: self.Age,
            name: String::from_str(pdb_name).unwrap(),
            guid: guid,
        }
    }
}

#[allow(non_camel_case_types, dead_code, non_snake_case)]
#[repr(C)]
struct CV_INFO_PDB20 {
    pub CvSignature: u32,
    pub Offset: u32,
    pub Signature: u32,
    pub Age: u32,
    pub PdbFileName: [u8; 1],
}

impl CV_INFO_PDB20 {
    /// 获取DPB下载路径
    #[allow(dead_code)]
    pub fn pdb_url(&self) -> String {
        let cpdb_name = unsafe { CStr::from_ptr(self.PdbFileName.as_ptr() as _) };
        let pdb_name = cpdb_name.to_str().unwrap_or("unknown");
        format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
            pdb_name, self.Signature, self.Age, pdb_name
        )
    }
    pub fn pdb_info(&self) -> PdbInfo {
        let cpdb_name = unsafe { CStr::from_ptr(self.PdbFileName.as_ptr() as _) };
        let pdb_name = cpdb_name.to_str().unwrap_or("unknown");
        PdbInfo {
            age: self.Age,
            name: String::from_str(pdb_name).unwrap(),
            guid: format!("{}", self.Signature),
        }
    }
}
/// 解析 code_view信息
fn parse_code_view_info(pe: *const u8, debug_entry: &IMAGE_DEBUG_DIRECTORY) -> Option<PdbInfo> {
    // 获取 CodeView 数据指针
    unsafe {
        let cv_data_ptr = pe.add(debug_entry.PointerToRawData as usize);
        let sign = (cv_data_ptr as *const [u8; 4]).read();
        if let Ok(sign_str) = str::from_utf8(&sign) {
            println!("{}", sign_str);
            return match sign_str {
                CV_SIGNATURE_RSDS => {
                    let pdb = &*(cv_data_ptr as *const CV_INFO_PDB70);
                    return Some(pdb.pdb_info());
                }
                CV_SIGNATURE_NB10 => {
                    let pdb = &*(cv_data_ptr as *const CV_INFO_PDB20);
                    Some(pdb.pdb_info())
                }
                _ => None,
            };
        }
    }
    None
}

/// RVA转文件偏移
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn rva_to_offset(
    sections: *const IMAGE_SECTION_HEADER,
    num_sections: u16,
    rva: u32,
) -> Option<u32> {
    for i in 0..num_sections {
        // 检查RVA是否在这个节区的内存范围内
        unsafe {
            let section = &*(sections.offset(i as isize));
            let va_start = section.VirtualAddress;
            let va_end = va_start + section.SizeOfRawData; // 使用 SizeOfRawData 更安全

            if rva >= va_start && rva < va_end {
                return Some(rva - va_start + section.PointerToRawData);
            }
        }
    }
    None
}

/// 通过模块文件查询函数偏移地址
pub fn find_func_with_module(func_name: &str, module: &[u8]) -> Option<u32> {
    use pdb::FallibleIterator;
    if let Ok(pdb_info) = unsafe { pdb_info(module.as_ptr()) } {
        // 检查缓存
        let tmp_pdb = format!(
            "{}{}{}{}",
            std::env::temp_dir().to_str().unwrap(),
            pdb_info.guid,
            pdb_info.age,
            pdb_info.name
        );
        println!("临时文件:{}", tmp_pdb);
        if !std::fs::exists(&tmp_pdb).unwrap() {
            println!("文件不存在:{}", tmp_pdb);
            // 文件不存在
            let pdb_url = format!(
                "https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
                pdb_info.name, pdb_info.guid, pdb_info.age, pdb_info.name
            );
            // fffff806`71c58000  //8bb960
            println!("pdb地址：{}", pdb_url);
            {
                let response = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(60 * 10))
                    .connect_timeout(Duration::from_secs(60 * 10))
                    .build()
                    .unwrap()
                    .get(&pdb_url)
                    .timeout(Duration::from_secs(60 * 10))
                    .send()
                    .unwrap();
                let bytes = response.bytes().unwrap();
                let _ = std::fs::write(&tmp_pdb, bytes);
            }
        }
        return find_func_with_pdb(func_name, &tmp_pdb);
    }
    None
}

/// 通过PDB查询函数偏移地址
pub fn find_func_with_pdb(func_name: &str, pdb_path: &str) -> Option<u32> {
    use pdb::FallibleIterator;
    if let Ok(file) = std::fs::File::open(pdb_path) {
        let mut pdb = pdb::PDB::open(file).unwrap();
        let address_map = pdb.address_map().unwrap();
        // 获取全局符号表
        let symbol_table = pdb.global_symbols().unwrap();
        // 获取类型信息（用于解析函数参数等）
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next().unwrap() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(ref data)) => {
                    let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                    let func = data.name.to_string();
                    if func_name.eq(func.trim()) {
                        println!("{}:{}", func_name, rva);
                        return Some(rva.0);
                    }
                }
                _ => {

                }
            }
        }
    }
    None
}
