// Rust花指令生成添加器
// 功能：向PE文件添加花指令以提高程序反分析能力

use egui::{Context, RichText, Color32, ScrollArea, Visuals};
use eframe::{App, Frame, NativeOptions};
// 暂时注释pecs库，实现基本的花指令添加功能
use sha2::{Digest, Sha256};
use rand::Rng;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use log::{info, error, warn};

// 花指令类型枚举
#[derive(Clone, Copy, PartialEq, Debug)]
enum JunkCodeType {
    RandomInstructions,     // 随机无意义指令
    JumpConfusion,          // 跳转混淆
    ControlFlowFlattening,  // 控制流平坦化
    FakeControlFlow,        // 虚假控制流
    InstructionSubstitution, // 指令替换
}

// 花指令强度级别
#[derive(Clone, Copy, PartialEq, Debug)]
enum JunkCodeStrength {
    Level1,  // 最弱
    Level2,
    Level3,
    Level4,
    Level5,  // 最强
}

// 寄存器选择状态
#[derive(Clone)]
struct RegisterSelection {
    eax: bool,
    ebx: bool,
    ecx: bool,
    edx: bool,
    esi: bool,
    edi: bool,
    ebp: bool,
    esp: bool,
}

// 应用程序状态
#[derive(Clone)]
struct JunkCodeApp {
    // 文件相关
    target_file: Option<PathBuf>,
    file_content: Option<Vec<u8>>,
    original_hash: String,
    processed_hash: String,
    file_info: String,
    
    // 花指令配置
    junk_code_type: JunkCodeType,
    junk_code_strength: JunkCodeStrength,
    max_code_length: u32,
    transform_count: u32,
    registers: RegisterSelection,
    show_memory_offset: bool,
    use_relative_offset: bool,
    show_machine_code: bool,
    
    // 生成的花指令
    generated_code: String,
    generated_bytes: Vec<u8>,
    
    // 状态和错误信息
    status_message: String,
    error_message: String,
    is_processing: bool,
    
    // 花指令模板（可自定义）
    custom_templates: Vec<String>,
}

impl Default for JunkCodeApp {
    fn default() -> Self {
        Self {
            target_file: None,
            file_content: None,
            original_hash: "".to_string(),
            processed_hash: "".to_string(),
            file_info: "".to_string(),
            junk_code_type: JunkCodeType::RandomInstructions,
            junk_code_strength: JunkCodeStrength::Level3,
            max_code_length: 500,
            transform_count: 10000,
            registers: RegisterSelection {
                eax: true,
                ebx: true,
                ecx: true,
                edx: true,
                esi: true,
                edi: true,
                ebp: true,
                esp: false, // 默认不使用ESP以避免栈问题
            },
            show_memory_offset: true,
            use_relative_offset: true,
            show_machine_code: true,
            generated_code: "".to_string(),
            generated_bytes: Vec::new(),
            status_message: "准备就绪".to_string(),
            error_message: "".to_string(),
            is_processing: false,
            custom_templates: Vec::new(),
        }
    }
}

impl JunkCodeApp {
    // 计算文件哈希值
    fn calculate_file_hash(&self) -> String {
        if let Some(content) = &self.file_content {
            let mut hasher = Sha256::new();
            hasher.update(content);
            format!("{:x}", hasher.finalize())
        } else {
            "".to_string()
        }
    }
    
    // 生成随机花指令
    fn generate_junk_code(&mut self) {
        let mut rng = rand::thread_rng();
        let mut code = String::new();
        let mut bytes = Vec::new();
        
        // 根据强度确定指令数量
        let instruction_count = match self.junk_code_strength {
            JunkCodeStrength::Level1 => 10 + rng.gen_range(0..20),
            JunkCodeStrength::Level2 => 30 + rng.gen_range(0..50),
            JunkCodeStrength::Level3 => 80 + rng.gen_range(0..120),
            JunkCodeStrength::Level4 => 200 + rng.gen_range(0..300),
            JunkCodeStrength::Level5 => 500 + rng.gen_range(0..500),
        };
        
        // 根据选择的花指令类型生成代码
        match self.junk_code_type {
            JunkCodeType::RandomInstructions => {
                self.generate_random_instructions(instruction_count, &mut rng, &mut code, &mut bytes);
            },
            JunkCodeType::JumpConfusion => {
                self.generate_jump_confusion(instruction_count, &mut rng, &mut code, &mut bytes);
            },
            JunkCodeType::ControlFlowFlattening => {
                self.generate_control_flow_flattening(instruction_count, &mut rng, &mut code, &mut bytes);
            },
            JunkCodeType::FakeControlFlow => {
                self.generate_fake_control_flow(instruction_count, &mut rng, &mut code, &mut bytes);
            },
            JunkCodeType::InstructionSubstitution => {
                self.generate_instruction_substitution(instruction_count, &mut rng, &mut code, &mut bytes);
            },
        }
        
        self.generated_code = code;
        let bytes_len = bytes.len();
        self.generated_bytes = bytes;
        self.status_message = format!("生成了 {} 字节的花指令", bytes_len);
    }
    
    // 生成随机无意义指令
    fn generate_random_instructions<R: Rng>(&self, count: usize, rng: &mut R, code: &mut String, bytes: &mut Vec<u8>) {
        // 使用向量和字符串的组合表示指令，统一类型结构
        let basic_instructions = [
            (vec![0x90], "nop"),                                // 空操作
            (vec![0x83, 0xC0, 0x01], "add eax, 1"),              // eax += 1
            (vec![0x83, 0xC0, 0x02], "add eax, 2"),              // eax += 2
            (vec![0x83, 0xE8, 0x01], "sub eax, 1"),              // eax -= 1
            (vec![0x83, 0xC3, 0x01], "add ebx, 1"),              // ebx += 1
            (vec![0x83, 0xEB, 0x01], "sub ebx, 1"),              // ebx -= 1
            (vec![0x83, 0xC1, 0x01], "add ecx, 1"),              // ecx += 1
            (vec![0x83, 0xE9, 0x01], "sub ecx, 1"),              // ecx -= 1
            (vec![0x83, 0xC2, 0x01], "add edx, 1"),              // edx += 1
            (vec![0x83, 0xEA, 0x01], "sub edx, 1"),              // edx -= 1
            (vec![0x83, 0xC6, 0x01], "add esi, 1"),              // esi += 1
            (vec![0x83, 0xEE, 0x01], "sub esi, 1"),              // esi -= 1
            (vec![0x83, 0xC7, 0x01], "add edi, 1"),              // edi += 1
            (vec![0x83, 0xEF, 0x01], "sub edi, 1"),              // edi -= 1
        ];
        
        for i in 0..count {
            // 使用标准随机索引选择
            let idx = rng.gen_range(0..basic_instructions.len());
            let (opcodes, mnemonic) = &basic_instructions[idx];
            
            // 添加操作码到字节向量
            bytes.extend_from_slice(opcodes);
            
            // 根据配置格式化输出
            if self.show_memory_offset && self.show_machine_code {
                let op_str: String = opcodes.iter().map(|op| format!("{:02x}", op)).collect::<Vec<_>>().join(" ");
                code.push_str(&format!("0000000{:02x}: {} {}\n", i, op_str, mnemonic));
            } else if self.show_memory_offset {
                code.push_str(&format!("0000000{:02x}: {}\n", i, mnemonic));
            } else if self.show_machine_code {
                let op_str: String = opcodes.iter().map(|op| format!("{:02x}", op)).collect::<Vec<_>>().join(" ");
                code.push_str(&format!("{} {}\n", op_str, mnemonic));
            } else {
                code.push_str(&format!("{}\n", mnemonic));
            }
        }
    }
    
    // 生成跳转混淆
    fn generate_jump_confusion<R: Rng>(&self, count: usize, rng: &mut R, code: &mut String, bytes: &mut Vec<u8>) {
        // 简单的跳转混淆示例
        let jump_instructions = [
            (vec![0xEB, 0x01], "jmp +1"),  // 短跳转
            (vec![0x90], "nop"),           // 空操作
        ];
        
        for i in 0..count {
            if i % 3 == 0 {
                // 添加跳转指令
                bytes.extend_from_slice(&[0xEB, 0x03]); // jmp +3
                code.push_str(&format!("{:08x}: EB 03 jmp +3\n", i));
                bytes.extend_from_slice(&[0x90, 0x90, 0x90]); // 3个nop
                code.push_str(&format!("{:08x}: 90 nop\n", i+1));
                code.push_str(&format!("{:08x}: 90 nop\n", i+2));
                code.push_str(&format!("{:08x}: 90 nop\n", i+3));
            } else {
                // 添加普通指令
                // 使用标准随机索引选择，避免使用IteratorRandom trait
                let idx = rng.gen_range(0..jump_instructions.len());
                let (opcodes, mnemonic) = &jump_instructions[idx];
                
                bytes.extend_from_slice(opcodes);
                let op_str: String = opcodes.iter().map(|op| format!("{:02x}", op)).collect::<Vec<_>>().join(" ");
                code.push_str(&format!("{:08x}: {} {}\n", i, op_str, mnemonic));
            }
        }
    }
    
    // 生成控制流平坦化
    fn generate_control_flow_flattening<R: Rng>(&self, count: usize, rng: &mut R, code: &mut String, bytes: &mut Vec<u8>) {
        // 控制流平坦化示例
        code.push_str("// 控制流平坦化示例\n");
        code.push_str("push eax\n");
        code.push_str("push ebx\n");
        code.push_str("mov eax, 0\n");
        code.push_str("jmp dispatch\n");
        
        // 添加多个代码块
        for i in 0..count/10 {
            code.push_str(&format!("block_{}:\n", i));
            self.generate_random_instructions(5, rng, code, bytes);
            code.push_str(&format!("mov eax, {}\n", i+1));
            code.push_str("jmp dispatch\n");
        }
        
        code.push_str("dispatch:\n");
        code.push_str("cmp eax, 10\n");
        code.push_str("jge end\n");
        code.push_str("jmp [jump_table + eax*4]\n");
        code.push_str("end:\n");
        code.push_str("pop ebx\n");
        code.push_str("pop eax\n");
        
        // 添加一些实际的机器码
        bytes.extend_from_slice(&[0x50, 0x53]); // push eax, push ebx
        bytes.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0
    }
    
    // 生成虚假控制流
    fn generate_fake_control_flow<R: Rng>(&self, count: usize, rng: &mut R, code: &mut String, bytes: &mut Vec<u8>) {
        // 虚假控制流示例
        for i in 0..count/5 {
            // 生成永远不会执行的代码路径
            code.push_str(&format!("// 虚假路径 {}\n", i));
            code.push_str("cmp eax, 0xFFFFFFFF\n");
            code.push_str("je fake_path\n");
            code.push_str("real_path:\n");
            self.generate_random_instructions(3, rng, code, bytes);
            code.push_str("jmp next\n");
            code.push_str("fake_path:\n");
            self.generate_random_instructions(5, rng, code, bytes);
            code.push_str("next:\n");
            
            // 添加机器码
            bytes.extend_from_slice(&[0x83, 0xF8, 0xFF]); // cmp eax, 0xFFFFFFFF
            bytes.extend_from_slice(&[0x74, 0x03]); // je fake_path
        }
    }
    
    // 生成指令替换
    fn generate_instruction_substitution<R: Rng>(&self, count: usize, rng: &mut R, code: &mut String, bytes: &mut Vec<u8>) {
        // 指令替换示例（用等效但更长的指令序列替换简单指令）
        let substitutions = [
            ([0x50, 0x40, 0x58], "// add eax, 1 的等效替换: push eax, inc eax, pop eax"),
            ([0x50, 0x48, 0x58], "// sub eax, 1 的等效替换: push eax, dec eax, pop eax"),
        ];
        
        for _i in 0..count/3 {
            // 使用标准随机索引选择，避免使用IteratorRandom trait
            let idx = rng.gen_range(0..substitutions.len());
            let (inst_bytes, comment) = &substitutions[idx];
            
            code.push_str(&format!("{}\n", comment));
            bytes.extend_from_slice(inst_bytes);
            for b in inst_bytes {
                code.push_str(&format!("{:02x} ", b));
            }
            code.push_str("\n");
        }
    }
    
        // 基本的PE文件操作函数
    fn add_junk_code_to_pe(&self, original_content: &[u8], junk_code: &[u8]) -> Result<Vec<u8>, String> {
        // 全面的PE文件验证
        if original_content.len() < 0x40 {
            return Err("文件太小，不是有效的PE文件".to_string());
        }
        
        // 检查MZ头
        if &original_content[0..2] != b"MZ" {
            return Err("文件缺少MZ头，不是有效的PE文件".to_string());
        }
        
        // 获取PE签名偏移
        let pe_offset = original_content[0x3C] as usize;
        if pe_offset + 3 >= original_content.len() {
            return Err("文件格式异常：无法找到PE签名".to_string());
        }
        
        // 检查PE签名，确保边界安全
        let pe_signature_bytes = original_content.get(pe_offset..pe_offset+2)
            .ok_or("无法访问PE签名区域".to_string())?;
        if pe_signature_bytes != b"PE" {
            return Err(format!("文件缺少PE签名，不是有效的PE文件（找到: {:?}）", pe_signature_bytes).to_string());
        }
        
        // PE头偏移（PE签名后）
        let pe_header_offset = pe_offset + 4;
        
        // 创建文件副本
        let mut modified_content = original_content.to_vec();
        
        // 读取文件头信息
        let _machine_type_bytes = modified_content.get(pe_header_offset..pe_header_offset+2).ok_or("无法读取机器类型".to_string())?;
        let number_of_sections = modified_content.get(pe_header_offset + 6).ok_or("无法读取节数量".to_string())?;
        let optional_header_size_bytes = modified_content.get(pe_header_offset + 20..pe_header_offset + 22).ok_or("无法读取可选头大小".to_string())?;
        
        let number_of_sections = *number_of_sections as usize;
        let optional_header_size = u16::from_le_bytes(optional_header_size_bytes.try_into().map_err(|_| "无效的可选头大小数据".to_string())?) as usize;
        
        // 验证节数量合理性（PE格式理论上最多支持255个节）
        if number_of_sections == 0 || number_of_sections > 255 {
            return Err(format!("无效的节数量: {}", number_of_sections).to_string());
        }
        
        // 计算节表偏移
        let section_table_offset = pe_header_offset + 24 + optional_header_size;
        
        // 检查节表是否在文件范围内
        if section_table_offset + number_of_sections * 40 > modified_content.len() {
            return Err("节表超出文件范围".to_string());
        }
        
        // 获取对齐值
        let mut file_alignment = 512; // 默认512字节对齐
        let mut section_alignment = 4096; // 默认4KB对齐
        
        // 尝试从可选头读取对齐值
        if pe_header_offset + 24 + 16 < modified_content.len() { // 确保有足够空间
            // 检查文件是否为PE32或PE32+
            let magic_bytes = modified_content.get(pe_header_offset + 24..pe_header_offset + 26).ok_or("无法读取PE格式标识".to_string())?;
            let magic = u16::from_le_bytes(magic_bytes.try_into().map_err(|_| "无效的PE格式标识".to_string())?);
            
            // 根据PE类型读取适当的对齐值
            if magic == 0x10B { // PE32
                if pe_header_offset + 24 + 32 < modified_content.len() {
                    file_alignment = u32::from_le_bytes(
                        modified_content.get(pe_header_offset + 24 + 32..pe_header_offset + 24 + 36)
                            .ok_or("无法读取文件对齐".to_string())?
                            .try_into().map_err(|_| "无效的文件对齐数据".to_string())?
                    );
                }
                if pe_header_offset + 24 + 36 < modified_content.len() {
                    section_alignment = u32::from_le_bytes(
                        modified_content.get(pe_header_offset + 24 + 36..pe_header_offset + 24 + 40)
                            .ok_or("无法读取节对齐".to_string())?
                            .try_into().map_err(|_| "无效的节对齐数据".to_string())?
                    );
                }
            } else if magic == 0x20B { // PE32+
                if pe_header_offset + 24 + 32 < modified_content.len() {
                    file_alignment = u32::from_le_bytes(
                        modified_content.get(pe_header_offset + 24 + 32..pe_header_offset + 24 + 36)
                            .ok_or("无法读取文件对齐".to_string())?
                            .try_into().map_err(|_| "无效的文件对齐数据".to_string())?
                    );
                }
                if pe_header_offset + 24 + 36 < modified_content.len() {
                    section_alignment = u32::from_le_bytes(
                        modified_content.get(pe_header_offset + 24 + 36..pe_header_offset + 24 + 40)
                            .ok_or("无法读取节对齐".to_string())?
                            .try_into().map_err(|_| "无效的节对齐数据".to_string())?
                    );
                }
            }
            
            // 验证对齐值合理性
            if file_alignment == 0 || (file_alignment & (file_alignment - 1)) != 0 {
                file_alignment = 512; // 如果无效，使用默认值
            }
            if section_alignment == 0 || (section_alignment & (section_alignment - 1)) != 0 {
                section_alignment = 4096; // 如果无效，使用默认值
            }
        }
        
        // 获取最后一个节的信息
        let last_section_offset = section_table_offset + (number_of_sections - 1) * 40;
        
        // 读取并更新节的虚拟大小（按节对齐进行调整）
        let virtual_size_bytes = modified_content.get(last_section_offset + 8..last_section_offset + 12)
            .ok_or("无法读取虚拟大小".to_string())?;
        let virtual_size = u32::from_le_bytes(virtual_size_bytes.try_into().map_err(|_| "无效的虚拟大小数据".to_string())?);
        
        let new_virtual_size = virtual_size + junk_code.len() as u32;
        // 按照节对齐进行调整
        let aligned_virtual_size = ((new_virtual_size + section_alignment - 1) / section_alignment) * section_alignment;
        
        modified_content[last_section_offset + 8..last_section_offset + 12]
            .copy_from_slice(&aligned_virtual_size.to_le_bytes());
        
        // 读取并更新节的原始大小（按文件对齐进行调整）
        let raw_size_bytes = modified_content.get(last_section_offset + 16..last_section_offset + 20)
            .ok_or("无法读取原始大小".to_string())?;
        let raw_size = u32::from_le_bytes(raw_size_bytes.try_into().map_err(|_| "无效的原始大小数据".to_string())?);
        
        let new_raw_size = raw_size + junk_code.len() as u32;
        // 按照文件对齐进行调整
        let aligned_raw_size = ((new_raw_size + file_alignment - 1) / file_alignment) * file_alignment;
        
        modified_content[last_section_offset + 16..last_section_offset + 20]
            .copy_from_slice(&aligned_raw_size.to_le_bytes());
        
        // 确保节是可执行的
        let characteristics_bytes = modified_content.get(last_section_offset + 36..last_section_offset + 40)
            .ok_or("无法读取节特性".to_string())?;
        let mut characteristics = u32::from_le_bytes(characteristics_bytes.try_into().map_err(|_| "无效的节特性数据".to_string())?);
        characteristics |= 0x20000000; // 设置可执行标志
        modified_content[last_section_offset + 36..last_section_offset + 40]
            .copy_from_slice(&characteristics.to_le_bytes());
        
        // 在文件末尾添加花指令数据
        modified_content.extend_from_slice(junk_code);
        
        info!("成功添加了 {} 字节的花指令到文件", junk_code.len());
        Ok(modified_content)
    }
    
    // 添加花指令到PE文件 - 对外接口
    fn add_junk_code_to_pe_file(&mut self) -> Result<(), String> {
        // 先生成花指令，避免借用冲突
        if self.generated_bytes.is_empty() {
            self.generate_junk_code();
        }
        
        if let Some(file_path) = &self.target_file {
            if let Some(original_content) = &self.file_content {
                // 移除了备份功能，直接处理文件
                
                // 添加花指令
                match self.add_junk_code_to_pe(original_content, &self.generated_bytes) {
                    Ok(modified_content) => {
                        // 生成处理后的文件名
                        let processed_file_name = if self.processed_hash.is_empty() {
                            // 第一次处理
                            format!("{}_processed.exe", file_path.file_stem().unwrap_or_default().to_string_lossy())
                        } else {
                            // 重复处理 - 使用递增的编号
                            let base_name = file_path.file_stem().unwrap_or_default().to_string_lossy();
                            let mut counter = 2;
                            let mut candidate_name: String;
                            
                            // 查找可用的递增编号
                            loop {
                                candidate_name = format!("{}_processed_{}.exe", base_name, counter);
                                let candidate_path = file_path.with_file_name(&candidate_name);
                                if !candidate_path.exists() {
                                    break;
                                }
                                counter += 1;
                            }
                            candidate_name
                        };
                        
                        let processed_path = file_path.with_file_name(processed_file_name);
                        fs::write(&processed_path, &modified_content)
                            .map_err(|e| format!("保存处理后文件失败: {}", e))?;
                        
                        // 更新应用状态，允许重复添加花指令
                        // 1. 更新文件内容为处理后的内容
                        self.file_content = Some(modified_content.clone());
                        // 2. 更新文件路径为处理后的文件路径
                        self.target_file = Some(processed_path.clone());
                        // 3. 计算处理后的哈希值
                        let mut hasher = Sha256::new();
                        hasher.update(&modified_content);
                        self.processed_hash = format!("{:x}", hasher.finalize());
                        
                        self.status_message = format!("花指令添加成功！处理后文件: {}", processed_path.display());
                        // 重置处理状态，允许再次处理
                        self.is_processing = false;
                        return Ok(());
                    },
                    Err(e) => {
                        error!("添加花指令失败: {}", e);
                        // 确保在错误路径也重置处理状态
                        self.is_processing = false;
                        return Err(format!("添加花指令失败: {}", e));
                    }
                }
            }
        }
        // 确保在未选择文件的情况下也重置处理状态
        self.is_processing = false;
        Err("请先选择目标文件".to_string())
    }
    
    // 加载目标文件
    fn load_target_file(&mut self, path: PathBuf) -> Result<(), String> {
        // 完全重置所有相关状态，确保没有之前文件的残留信息
        self.processed_hash.clear();
        self.generated_code.clear();
        self.generated_bytes.clear();
        self.error_message.clear();
        self.file_info.clear(); // 清空文件信息，避免残留
        
        if !path.exists() || !path.is_file() {
            return Err("文件不存在或不是有效的文件".to_string());
        }
        
        // 放宽扩展名检查，接受常见的Windows可执行文件格式
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            let supported_exts = ["exe", "dll", "sys", "ocx", "scr", "drv"];
            if !supported_exts.contains(&ext_lower.as_str()) {
                // 即使扩展名不匹配，也继续尝试验证PE结构，只是给出警告
                self.file_info = "⚠️ 文件扩展名可能不匹配，尝试继续验证PE结构\n".to_string();
            }
        } else {
            self.file_info = "⚠️ 文件没有扩展名，尝试继续验证PE结构\n".to_string();
        }
        
        // 读取文件内容
        let mut file = File::open(&path)
            .map_err(|e| format!("打开文件失败: {}", e))?;
        
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| format!("读取文件失败: {}", e))?;
        
        self.target_file = Some(path.clone());
        self.file_content = Some(content);
        self.original_hash = self.calculate_file_hash();
        
        // 解析PE文件获取详细信息
        if let Some(content) = &self.file_content {
            let mut file_info = vec![format!("文件: {}", path.display())];
            let mut is_valid_pe = false;
            
            // 1. 验证DOS头
            if content.len() >= 0x40 && &content[0..2] == b"MZ" {
                file_info.push("✓ DOS头验证通过".to_string());
                
                // 2. 获取PE签名偏移并验证 - 修正为正确读取4字节LONG类型
                let pe_offset = u32::from_le_bytes(
                    content[0x3C..0x40].try_into().unwrap_or_default()
                ) as usize;
                
                // 验证完整的4字节PE签名 "PE\0\0"
                if pe_offset + 4 <= content.len() && &content[pe_offset..pe_offset+4] == b"PE\0\0" {
                    file_info.push("✓ PE签名验证通过".to_string());
                    
                    // 3. PE头偏移（PE签名后）
                    let pe_header_offset = pe_offset + 4;
                    
                    // 4. 验证文件头基本信息
                    if pe_header_offset + 6 < content.len() {
                        // 机器类型检测 - 扩展支持更多常见处理器架构
                        let machine_type = u16::from_le_bytes(
                            content[pe_header_offset..pe_header_offset+2].try_into().unwrap_or_default()
                        );
                        let machine_desc = match machine_type {
                            0x014C => "x86 (Intel 386)",
                            0x8664 => "x64 (AMD64)",
                            0x0200 => "IA64 (Intel Itanium)",
                            0x1C0 => "ARM little endian",
                            0xAA64 => "ARM64 (AArch64)",
                            0xEBC => "EFI Byte Code",
                            0x9041 => "MIPS little endian",
                            0x266 => "MIPS R4000 big endian",
                            0x1F0 => "PowerPC little endian",
                            0x1F1 => "PowerPC big endian",
                            0x166 => "MIPS16",
                            0x1A2 => "MIPS with FPU",
                            0x169 => "MIPS16 with FPU",
                            _ => &format!("未知 (0x{:X})", machine_type)
                        };
                        file_info.push(format!("✓ 机器类型: {}", machine_desc));
                        
                        // 节数量
                        let number_of_sections = content[pe_header_offset + 6];
                        file_info.push(format!("✓ 节数量: {}", number_of_sections));
                        
                        // 5. 检查可选头
                        let optional_header_size_bytes = &content[pe_header_offset + 20..pe_header_offset + 22];
                        let optional_header_size = u16::from_le_bytes(optional_header_size_bytes.try_into().unwrap_or_default()) as usize;
                        
                        if optional_header_size > 0 && pe_header_offset + 24 + optional_header_size <= content.len() {
                            // 确定PE文件类型（PE32或PE32+）
                            let magic = u16::from_le_bytes(
                                content[pe_header_offset + 24..pe_header_offset + 26].try_into().unwrap_or_default()
                            );
                            let pe_type = match magic {
                                0x10B => "PE32 (32位)",
                                0x20B => "PE32+ (64位)",
                                _ => &format!("未知格式 (0x{:X})", magic)
                            };
                            file_info.push(format!("✓ PE类型: {}", pe_type));
                            
                            // 尝试读取子系统信息（决定程序运行环境）
                            let subsystem_offset = if magic == 0x10B { // PE32
                                pe_header_offset + 24 + 68
                            } else { // PE32+
                                pe_header_offset + 24 + 72
                            };
                            
                            if subsystem_offset + 2 <= content.len() {
                                let subsystem = u16::from_le_bytes(
                                    content[subsystem_offset..subsystem_offset+2].try_into().unwrap_or_default()
                                );
                                let subsystem_desc = match subsystem {
                                      1 => "原生系统（驱动程序）",
                                      2 => "Windows GUI应用",
                                      3 => "Windows控制台应用",
                                      7 => "POSIX控制台应用",
                                      9 => "Windows CE GUI应用",
                                      10 => "Windows CE控制台应用",
                                      11 => "EFI应用程序",
                                      12 => "EFI引导服务驱动程序",
                                      13 => "EFI运行时驱动程序",
                                      14 => "EFI ROM",
                                      15 => "Xbox",
                                      16 => "Windows Boot Application",
                                      17 => "Xbox One",
                                      _ => &format!("其他 (0x{:X})", subsystem)
                                  };
                                  file_info.push(format!("✓ 子系统: {}", subsystem_desc));
                            }
                            
                            // 改进节表验证，不再硬编码节表项大小
                            let section_table_offset = pe_header_offset + 24 + optional_header_size;
                            
                            // 标准PE文件节表项大小为40字节，但我们采用更灵活的方式验证
                            let section_entry_size = 40; // 节表项标准大小
                            let total_section_table_size = (number_of_sections as usize) * section_entry_size;
                            
                            // 放宽验证条件，只要节表偏移有效并且有足够空间容纳至少一个节表项，就认为是有效PE
                            if section_table_offset < content.len() {
                                if section_table_offset + total_section_table_size <= content.len() {
                                    file_info.push("✓ 节表验证通过".to_string());
                                    is_valid_pe = true;
                                } else if number_of_sections > 0 {
                                    // 即使整个节表超出文件范围，但只要节表偏移有效且有至少一个节表项，也认为基本有效
                                    file_info.push("⚠️ 节表部分超出文件范围，但检测到基本PE结构".to_string());
                                    is_valid_pe = true;
                                } else {
                                    file_info.push("✗ 节表偏移无效".to_string());
                                }
                            } else {
                                file_info.push("✗ 节表偏移无效".to_string());
                            }
                        } else {
                            file_info.push("✗ 可选头无效或不完整".to_string());
                        }
                    } else {
                        file_info.push("✗ PE文件头不完整".to_string());
                    }
                } else {
                    file_info.push("✗ PE签名验证失败".to_string());
                    error!("PE文件头验证失败: PE签名不正确或偏移无效");
                }
            } else {
                file_info.push("✗ DOS头验证失败".to_string());
                error!("MZ文件头验证失败: 文件太小或缺少MZ标识");
            }
            
            // 最终判定 - 采用更宽松但更准确的验证策略
            if is_valid_pe {
                file_info.push("✓ PE文件结构验证通过".to_string());
                info!("成功加载文件: {}, PE文件结构验证通过", path.display());
            } else {
                // 即使完整验证失败，也给出警告而不是直接拒绝
                file_info.push("⚠️ PE文件结构验证存在问题，但继续加载".to_string());
                warn!("PE文件结构验证存在问题，但继续加载: {}", path.display());
            }
            
            self.file_info = file_info.join("\n");
        }
        
        self.status_message = format!("已加载文件: {}", path.display());
        Ok(())
    }
    
    // 显示文件选择对话框
    fn show_file_dialog(&mut self) {
        // 确保在选择新文件前重置处理状态
        self.is_processing = false;
        
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("可执行文件", &["exe", "dll", "sys", "ocx", "scr", "cpl"])
            .pick_file() {
            if let Err(e) = self.load_target_file(path) {
                self.error_message = e;
                // 确保在加载失败时清除文件路径和内容，避免状态不一致
                self.target_file = None;
                self.file_content = None;
                self.file_info.clear();
            }
        }
    }
}

impl App for JunkCodeApp {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        // 错误消息处理
        if !self.error_message.is_empty() {
            egui::Window::new("错误")
                .resizable(false)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new(&self.error_message).color(Color32::RED));
                    if ui.button("确定").clicked() {
                        self.error_message.clear();
                    }
                });
        }
        
        // 主窗口布局，移除滚动区域，让内容自然适应窗口
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Rust花指令生成添加器");
            ui.separator();
            
            // 文件选择区域
            ui.label("目标文件:");
            ui.horizontal(|ui| {
                let mut path = "".to_string();
                if let Some(ref file_path) = self.target_file {
                    path = file_path.to_string_lossy().to_string();
                }
                ui.text_edit_singleline(&mut path);
                if ui.button("浏览...").clicked() {
                    self.show_file_dialog();
                }
            });
            
            // 文件拖放区域（暂不显示提示文字）
            // 注意：当前egui版本可能不支持drop_area，后续可更新实现拖放功能
            
            // 注意：当前egui版本可能不支持drop_area，后续可更新实现拖放功能
            
            // 文件信息显示
            if !self.file_info.is_empty() {
                ui.separator();
                ui.collapsing("文件信息", |ui| {
                    ui.label(&self.file_info);
                    if !self.original_hash.is_empty() {
                        ui.label(format!("原始文件哈希(SHA256): {}", self.original_hash));
                    }
                    if !self.processed_hash.is_empty() {
                        ui.label(format!("处理后哈希(SHA256): {}", self.processed_hash));
                    }
                });
            }
            
            ui.separator();
            
            // 花指令配置区域
            ui.heading("花指令设置");
            
            // 花指令类型选择
            ui.label("花指令类型:");
            ui.horizontal_wrapped(|ui| {
                if ui.radio_value(&mut self.junk_code_type, JunkCodeType::RandomInstructions, "随机指令").clicked() {
                    self.generated_code.clear();
                    self.generated_bytes.clear();
                }
                if ui.radio_value(&mut self.junk_code_type, JunkCodeType::JumpConfusion, "跳转混淆").clicked() {
                    self.generated_code.clear();
                    self.generated_bytes.clear();
                }
                if ui.radio_value(&mut self.junk_code_type, JunkCodeType::ControlFlowFlattening, "控制流平坦化").clicked() {
                    self.generated_code.clear();
                    self.generated_bytes.clear();
                }
                if ui.radio_value(&mut self.junk_code_type, JunkCodeType::FakeControlFlow, "虚假控制流").clicked() {
                    self.generated_code.clear();
                    self.generated_bytes.clear();
                }
                if ui.radio_value(&mut self.junk_code_type, JunkCodeType::InstructionSubstitution, "指令替换").clicked() {
                    self.generated_code.clear();
                    self.generated_bytes.clear();
                }
            });
            
            // 强度设置
            ui.label("强度级别:");
            ui.horizontal_wrapped(|ui| {
                ui.radio_value(&mut self.junk_code_strength, JunkCodeStrength::Level1, "级别1 (最弱)");
                ui.radio_value(&mut self.junk_code_strength, JunkCodeStrength::Level2, "级别2");
                ui.radio_value(&mut self.junk_code_strength, JunkCodeStrength::Level3, "级别3 (中等)");
                ui.radio_value(&mut self.junk_code_strength, JunkCodeStrength::Level4, "级别4");
                ui.radio_value(&mut self.junk_code_strength, JunkCodeStrength::Level5, "级别5 (最强)");
            });
            
            // 参数设置
            ui.horizontal(|ui| {
                ui.label("最大代码长度:");
                ui.add(egui::DragValue::new(&mut self.max_code_length).clamp_range(100..=u32::MAX));
                
                ui.label("变换次数:");
                ui.add(egui::DragValue::new(&mut self.transform_count).clamp_range(1000..=u32::MAX));
            });
            
            // 寄存器选择
            ui.label("使用寄存器:");
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.registers.eax, "EAX");
                ui.checkbox(&mut self.registers.ebx, "EBX");
                ui.checkbox(&mut self.registers.ecx, "ECX");
                ui.checkbox(&mut self.registers.edx, "EDX");
                ui.checkbox(&mut self.registers.esi, "ESI");
                ui.checkbox(&mut self.registers.edi, "EDI");
                ui.checkbox(&mut self.registers.ebp, "EBP");
                ui.checkbox(&mut self.registers.esp, "ESP");
            });
            
            // 显示选项
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.show_memory_offset, "显示内存偏移");
                ui.checkbox(&mut self.use_relative_offset, "使用相对偏移");
                ui.checkbox(&mut self.show_machine_code, "显示机器码");
            });
            
            // 操作按钮区域 - 优化样式
            ui.horizontal(|ui| {
                // 生成花指令按钮
                let generate_button = egui::Button::new("生成花指令")
                    .fill(egui::Color32::from_rgb(220, 230, 250))
                    .min_size(egui::vec2(120.0, 30.0));
                
                // 添加到文件按钮
                let add_button = egui::Button::new("添加到文件")
                    .fill(egui::Color32::from_rgb(200, 230, 200))
                    .min_size(egui::vec2(120.0, 30.0));
                
                if ui.add(generate_button).clicked() {
                    self.generate_junk_code();
                }
                
                ui.add_space(10.0);
                
                if ui.add(add_button).clicked() && !self.is_processing {
                    self.is_processing = true;
                    let app = Arc::new(Mutex::new(self.clone()));
                    
                    std::thread::spawn(move || {
                        let mut app = app.lock().unwrap();
                        if let Err(e) = app.add_junk_code_to_pe_file() {
                            app.error_message = e;
                        }
                        app.is_processing = false;
                    });
                }
                
                // 显示处理状态
                if self.is_processing {
                    ui.add_space(10.0);
                    ui.spinner();
                    ui.label("处理中...");
                }
            });
            
            // 始终显示代码统计信息 - 放在显眼位置
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("代码统计:").strong());
                ui.add_space(5.0);
                ui.label(egui::RichText::new(format!("{} 字节, {} 行", 
                    self.generated_bytes.len(), 
                    self.generated_code.lines().count())).color(egui::Color32::BLUE));
            });
            
            // 生成的花指令预览
            if !self.generated_code.is_empty() {
                ui.separator();
                ui.heading("生成的花指令预览");
                ui.add_space(5.0);
                
                // 优化的预览区域，将滚动条放入内容区域内
                let preview_frame = egui::Frame::default()
                    .fill(egui::Color32::WHITE)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::LIGHT_GRAY))
                    .rounding(4.0)
                    .inner_margin(4.0);
                
                preview_frame.show(ui, |ui| {
                    // 使用单一的ScrollArea包装文本，同时支持垂直和水平滚动
                    ScrollArea::both()
                        .max_height(300.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // 添加适当的内边距
                            ui.add_space(10.0);
                            // 显示代码内容
                            ui.monospace(&self.generated_code);
                            ui.add_space(10.0);
                        });
                });
            }
            
            // 状态栏
            ui.separator();
            ui.label(&self.status_message);
        });
    }
    
    // App trait 只需要实现update方法
    
    fn clear_color(&self, _visuals: &Visuals) -> [f32; 4] {
        // 设置背景颜色
        [0.95, 0.95, 0.95, 1.0]
    }
    
    // App trait 只需要实现update方法
}

fn main() {
    // 初始化日志系统
    env_logger::init();
    
    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("Rust花指令生成添加器 v0.1.1"),
        ..Default::default()
    };
    
    // 运行应用
    match eframe::run_native(
        "Rust花指令生成添加器",
        options,
        Box::new(|cc| {
            // 获取默认字体配置
            let mut fonts = egui::FontDefinitions::default();
            
            // 添加中文字体名称到默认字体家族
            fonts.font_data.insert(
                "simhei".to_owned(),
                egui::FontData::from_static(include_bytes!("C:/Windows/Fonts/simhei.ttf")),
            );
            
            // 设置字体优先级，确保中文字体能正常显示
            fonts.families.get_mut(&egui::FontFamily::Proportional)
                .unwrap()
                .insert(0, "simhei".to_owned());
            
            // 应用字体配置
            cc.egui_ctx.set_fonts(fonts);
            
            Box::new(JunkCodeApp::default())
        }),
    ) {
        Ok(_) => info!("应用程序正常退出"),
        Err(e) => error!("应用程序退出时出错: {:?}", e),
    }
}
