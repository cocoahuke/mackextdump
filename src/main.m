//
//  main.m
//  parseDisasmKexts_Mac
//
//  Created by huke on 8/10/16.
//  Copyright (c) 2016 com.cocoahuke. All rights reserved.
//

//parseDisasmKexts_Mac解析intel x86_64架构的内核扩展,可以保存输出为一个文件在分析时参数

#import <Foundation/Foundation.h>
#include "capstone/capstone.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/reloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <mach-o/nlist.h>

uint64_t rax;
uint64_t rbx;
uint64_t rcx;
uint64_t rdx;
uint64_t rdi;
uint64_t rsi;
uint64_t rbp;
uint64_t rsp;
uint64_t r8;
uint64_t r9;
uint64_t r10;
uint64_t r11;
uint64_t r12;
uint64_t r13;
uint64_t r14;
uint64_t r15;
uint64_t rip;


//machoH、文件相关函数
uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t FilegetSize(char *file_path);

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin);


int64_t getMEMOPoffset(csh handle,const cs_insn *insn); //得到lea指令的内存偏移数
int getMEMOPregister(csh handle,const cs_insn *insn); //得到lea指令的偏移寄存器

int getFirstReg(csh handle,const cs_insn *insn); //得到第一个寄存器
int getSecondReg(csh handle,const cs_insn *insn); //得到第二个寄存器

uint64_t getSingleIMM(csh handle,const cs_insn *insn); //得到单条指令的立即数

void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换汇编的虚拟内存地址,返回在内存中的实际内容

uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换虚拟内存地址,返回文件中偏移地址
//press here
uint64_t* getActualVarFromRegName(uint64_t address,int RegName);//根据寄存器名字得到对应的变量

//新しい函数
void getName_ClassAndFunc_of_Cpp(char *cpp_name,char *res[2]); //解析函数名从编译后的C++名字,返回字符串数组指针[0]Class[1]func 具体看下面用法

char *KextGetBundleID(void *bin);
//传入每个KEXT的二进制,返回该KEXT的CFBundleID

void ParseVtable(char *cn,uint64_t class_self,uint64_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff);//分析类的虚表

NSMutableDictionary *kernel_exportSym; //k:引用内核符号地址 v:符号名
NSMutableDictionary *exportSym; //正常符号表 //k:引用符号地址 v:符号名
void parse_symbols(void *buf);//解析符号段 New:解析内核导出函数

int check_PointerAddrInVM(uint64_t tar_addr);//检查指针指向位置是否在已分配的虚拟内存内,正确返回1

//下面的变量在基础IO类中收集的信息,在这个程序中为全局变量

char *cur_kext_path = NULL;

void start(const char *path){
    char *kext_path = (char*)path;
    cur_kext_path = kext_path;
    
    uint64_t kext_size = FilegetSize(kext_path);
    if(kext_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kext_bin = malloc(kext_size);
    
    FILE *fp = fopen(kext_path,"ro");
    if(fread(kext_bin,1,kext_size,fp)!=kext_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    parse_symbols(kext_bin);
    
    if(!kernel_exportSym){free(kext_bin);return;}
    if(!exportSym){free(kext_bin);return;}
    
    AnalysisModInitOfKEXT(kext_bin);
    free(kext_bin);
}

void usage(){
    printf("Usage: mackextdump [-s <specify a single exxc file of kext to analysis>] <Extensions folder>\n");
}

int check_file_exist(char *path){
    if(!access(path,F_OK)){
        if(!access(path,R_OK)){
            return 0;
        }
        return -1;
    }
    return -1;
}

int main(int argc, const char * argv[]) {
    
    const char *SINGLE_KEXT_EXEC_PATH = NULL;
    
    if(argc==1){
        printf("wrong args\n");usage();exit(1);
    }
    
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"-h")){
            usage();exit(1);
        }
        if(!strcmp(argv[i],"-s")){
            SINGLE_KEXT_EXEC_PATH = (i=i+1)>=argc?nil:argv[i];
            start(SINGLE_KEXT_EXEC_PATH);
            exit(1);
        }
    }
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *ext_path = [NSString stringWithUTF8String:argv[argc-1]];
    NSArray *kext_arr = [fm contentsOfDirectoryAtPath:ext_path error:nil];
    if(!kext_arr){
        printf("%s is a wrong path, please specify a Extensions folder that copy from /System/Library/Extensions\n",argv[argc-1]);exit(1);
    }
    for(int i=0;i<[kext_arr count];i++){
        NSString *MacOSpath = [NSString stringWithFormat:@"%@/%@/Contents/MacOS",ext_path,kext_arr[i]];
        if([fm fileExistsAtPath:MacOSpath]){
            NSArray *exec_arr = [fm contentsOfDirectoryAtPath:MacOSpath error:nil];
            NSString *exec_path = [NSString stringWithFormat:@"%@/%@",MacOSpath,exec_arr[0]];
            start([exec_path UTF8String]);
            //NSLog(@"%d: %@",i,kext_arr[i]);
        }
        else{
            //Doesn't have Macos folder
        }
    }
    
    return 0;
}


uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        return -1;
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
        return 0;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            /*case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }*/
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        return -1;
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
        return 0;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        return -1;
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
        return 0;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t FilegetSize(char *file_path){
    struct stat buf;
    if ( stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

#pragma mark imp:分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin){
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_X86,CS_MODE_64|CS_MODE_LITTLE_ENDIAN,&handle)!=CS_ERR_OK){
        printf("AnalysisModInitOfKEXT cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle,CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(bin,"__DATA","__mod_init_func");
    if(modInitVM==-1){
        return;
    }
    uint64_t modInitFileoff = machoGetFileAddr(bin,"__DATA","__mod_init_func");
    uint64_t modInitSize = machoGetSize(bin,"__DATA","__mod_init_func");
    
    //printf("\ntotal %llu modInit in \n",modInitSize/8);
    
    char *cn = NULL;
    
    for(int ab=0;ab<modInitSize/8;ab++){
        uint64_t *eachModInitEntry = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,modInitVM+ab*8);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff;//0x107c //0x278c //0x186b4
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry);//0x90caa07c //0x90cab78c //0x90cc16b4
        //printf("****************%d******\n",ab);
        printf("\n******** %d:%s *******\n",ab,KextGetBundleID(bin));
        printf("**%s**\n\n",cur_kext_path);
        count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        
        size_t j;
        
        rax = 0;
        rbx = 0;
        rcx = 0;
        rdx = 0;
        rdi = 0;
        rsi = 0;
        rbp = 0;
        rsp = 0;
        r8 = 0;
        r9 = 0;
        r10 = 0;
        r11 = 0;
        r12 = 0;
        r13 = 0;
        r14 = 0;
        r15 = 0;
        rip = 0;
        
        for(j=0;j<count;j++){
#pragma mark KEXT_DEBUG:输出汇编
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            //printf("r0:0x%x r1:0x%x r2:0x%x r3:0x%x\n",r0,r1,r2,r3);
            
#pragma mark KEXT_DEBUG:MOV OP
            if(strstr(insn[j].mnemonic,"mov")){
                int acount = cs_op_count(handle,&insn[j],X86_OP_REG);
                if(acount==2){
                    //两个寄存器之间的
                    //eg. mov rax,rdi
                }
                else if(acount==1){
                    //一个寄存器
                    int acount = cs_op_count(handle,&insn[j],ARM64_OP_IMM);
                    if(acount>0){
                        //立即数给寄存器
                        //eg. mov rax,0x4
                        
                        uint64_t imm = getSingleIMM(handle,&insn[j]);
                        int first_reg = getFirstReg(handle,&insn[j]);
                        
                        uint64_t* xx = getActualVarFromRegName(insn[j].address,first_reg);
                        if(!xx)
                            return;
                        if(xx){
                            *xx = imm;
                        }
                        
                    }else{
                        //没有立即数
                        int acount2 = cs_op_count(handle,&insn[j],ARM64_OP_MEM);
                        if(acount2){
                            //一个寄存器读取一个地址处的值
                            
                            int mem_reg = getMEMOPregister(handle,&insn[j]);
                            if(mem_reg==X86_REG_RIP){
                                //读取来自rip的偏移
                                //eg. mov rdx, qword ptr [rip + 0x9c7]
                                
                                uint64_t mem_offset = getMEMOPoffset(handle,&insn[j]);
                                int f_reg = getFirstReg(handle,&insn[j]);
                                uint64_t vmaddr = insn[j+1].address + mem_offset;
                                uint64_t *ref = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,vmaddr);
                                uint64_t* xx = getActualVarFromRegName(insn[j].address,f_reg);
                                if(!xx)
                                    return;
                                if(xx){
                                    *xx = *ref;
                                }
                            }
                            //end of acount2
                        }
                    }
                }
            }
            
            
#pragma mark KEXT_DEBUG:LEA OP
            if(strstr(insn[j].mnemonic,"lea")){
                
                int first_reg = getFirstReg(handle,&insn[j]);
                
                int64_t offset = getMEMOPoffset(handle,&insn[j]);
                int offset_reg = getMEMOPregister(handle,&insn[j]);
                
                uint64_t lea_ref_vm;
                
                if(offset_reg==X86_REG_RIP){
                    int64_t cur_ip = insn[j+1].address;
                    lea_ref_vm = cur_ip + offset;
                    if(cn){
                        ParseVtable(cn,rdi,rcx,bin,lea_ref_vm,getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,lea_ref_vm));
                        cn = NULL;
                    }
                    
                }
                else{
                    uint64_t* offset_xx = getActualVarFromRegName(insn[j].address,offset_reg);
                    if(!offset_xx)
                        return;
                    lea_ref_vm = *offset_xx + offset;
                }
                
                uint64_t* xx = getActualVarFromRegName(insn[j].address,first_reg);
                if(!xx)
                    return;
                if(xx){
                    *xx = lea_ref_vm;
                }
                
                //uint64_t *lea_ref_mem = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,lea_ref_vm);
            }
            
#pragma mark KEXT_DEBUG:CALL OP
            if(!strcmp(insn[j].mnemonic,"call")){
                uint64_t jump_to = getSingleIMM(handle,&insn[j]);
                if(jump_to){
                    
                    NSNumber *findkey = [NSNumber numberWithUnsignedLongLong:insn[j].address+1];
                    NSString *sym_name = [kernel_exportSym objectForKey:findkey];
                    if(sym_name&&[sym_name isEqualToString:@"__ZN11OSMetaClassC2EPKcPKS_j"]){
                        //意为调用OSMetaClass
                        printf("(0x%llx)->OSMetaClass:OSMetaClass call 4 args list\n",insn[j].address);
                        printf("rdi:0x%llx\n",rdi);
                        char *rsi_classname = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,rsi);
                        cn = rsi_classname;
                        printf("rsi:%s\n",rsi_classname);
                        printf("rdx:0x%llx\n",rdx);
                        printf("rcx:0x%llx\n",rcx);
                        
                        //printf("vtable:0x%llx\n",ip_addr+ip_offset);
                        
                        
                        
                        //
                        //printf("vtable:0x%llx\n",vtable_start);
                    }
                }
            }
            
#pragma mark KEXT_DEBUG:RET OP
            if(strstr(insn[j].mnemonic,"ret")){
                break;
            }
            
        }
        cs_free(insn,count);
        
    }
}

//转换汇编的虚拟内存地址,返回在内存中的实际内容
#pragma mark imp:转换汇编的虚拟内存地址,返回在内存中的实际内容
void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    //这里以当前函数VM地址计算,而不是以该二进制最小的VM地址计算的原因是,虽然该二进制总共映射到VM的大小肯定就是文件中的size,但VM地址是可以不连续的,仅仅对于函数时连续的.
    uint64_t offset = cur_VMAddr - CurFunc_VMbaseAddr;
    //这里可以对offset增加判断,比如不能小于0
    return bin+CurFunc_FilebaseAddr+offset;
}

//转换虚拟内存地址,返回文件中偏移地址
#pragma mark imp:转换虚拟内存地址,返回文件中偏移地址
uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    return (uint64_t)((uint64_t)CurFunc_FilebaseAddr+((uint64_t)cur_VMAddr-(uint64_t)CurFunc_VMbaseAddr));
}

//得到str/ldr指令的内存偏移数
#pragma mark imp:得到str/ldr指令的内存偏移数
int64_t getMEMOPoffset(csh handle,const cs_insn *insn){
    int64_t offset;
    int acount = cs_op_count(handle,insn,X86_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPoffset 多个偏移量\n");
        for (int i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_MEM,i);
            offset = insn->detail->x86.operands[index].mem.disp;
            return offset;
        }
    }
    return 0;
}

//得到lea指令的偏移寄存器
#pragma mark imp:得到lea指令的偏移寄存器
int getMEMOPregister(csh handle,const cs_insn *insn){
    uint32_t i,offset;
    int acount = cs_op_count(handle,insn,X86_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPregister 多个偏移量\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_MEM,i);
            offset = insn->detail->x86.operands[index].mem.base;
            return offset;
        }
    }
    return 0;
}

//得到第一个寄存器
#pragma mark imp:得到第一个寄存器
int getFirstReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,X86_OP_REG);
    if (acount) {
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,X86_OP_REG,i);
            if(i==1){
                s_reg = insn->detail->x86.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//得到第二个寄存器
#pragma mark imp:得到第二个寄存器
int getSecondReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,X86_OP_REG);
    if (acount) {
        if(acount<2)
            printf("getSecondReg 少于一个寄存器\n");
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,X86_OP_REG,i);
            if(i==2){
                s_reg = insn->detail->x86.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//得到单条指令的立即数
#pragma mark imp:得到单条指令的立即数
uint64_t getSingleIMM(csh handle,const cs_insn *insn){
    int i;
    uint64_t imm;
    int acount = cs_op_count(handle,insn,X86_OP_IMM);
    if (acount) {
        if(acount>1)
            printf("getSingleIMM 多个立即数\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,X86_OP_IMM,i);
            imm = insn->detail->x86.operands[index].imm;
            return imm;
        }
    }
    return 0;
}

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
#pragma mark imp:检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr)
{
    //仅限使用64位程序,32位请修改
    int pid = 0;
    pid_for_task(mach_task_self(),&pid);
    
    vm_map_t task = 0;
    task_for_pid(mach_task_self(),pid,&task);
    
    int avai = 0;
    
    kern_return_t ret;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0;
    while (1) {
        ret = vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        
        if (ret != KERN_SUCCESS)
            break;
        if(addr>0x7fff00000000)
            break;
        if(tar_addr>=addr&&tar_addr<=addr+size){
            avai = 1;
        }
        //printf("region 0x%lx - 0x%lx\n",addr,addr+size);
        addr = addr + size;
    }
    
    if(avai==1)
        return 1;
    else
        return 0;
    
    return 0;
}

//根据寄存器名字得到对应的变量
#pragma mark imp:根据寄存器名字得到对应的变量
uint64_t* getActualVarFromRegName(uint64_t address,int RegName){
    switch (RegName) {
        case X86_REG_RAX:
            return &rax;
            break;
        case X86_REG_RBX:
            return &rbx;
            break;
        case X86_REG_RCX:
            return &rcx;
            break;
        case X86_REG_RDX:
            return &rdx;
            break;
        case X86_REG_RDI:
            return &rdi;
            break;
        case X86_REG_RSI:
            return &rsi;
            break;
        case X86_REG_RBP:
            return &rbp;
            break;
        case X86_REG_RSP:
            return &rsp;
            break;
        case X86_REG_R8:
            return &r8;
            break;
        case X86_REG_R9:
            return &r9;
            break;
        case X86_REG_R10:
            return &r10;
            break;
        case X86_REG_R11:
            return &r11;
            break;
        case X86_REG_R12:
            return &r12;
            break;
        case X86_REG_R13:
            return &r13;
            break;
        case X86_REG_R14:
            return &r14;
            break;
        case X86_REG_R15:
            return &r15;
            break;
        case X86_REG_RIP:
            return &rip;
            break;
        default:
            break;
    }
#pragma mark USE_32Bit_Register
    switch (RegName) {
        case X86_REG_EAX:
            return &rax;
            break;
        case X86_REG_EBX:
            return &rbx;
            break;
        case X86_REG_ECX:
            return &rcx;
            break;
        case X86_REG_EDX:
            return &rdx;
            break;
        case X86_REG_EDI:
            return &rdi;
            break;
        case X86_REG_ESI:
            return &rsi;
            break;
        default:
            break;
    }
    printf("0x%llx getActualVarFromRegName 没有设置对应的寄存器\n",address);
    return NULL;
}

//解析符号段
#pragma mark imp:解析符号段
void parse_symbols(void *buf){
    //记录所有调用的地址和函数名
    //对静态地址用0xff填充,eg. 类的函数虚表
    
    struct mach_header *mh = buf;
    
    //检测Fat
    struct fat_header* fileStartAsFat = (struct fat_header*)buf;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("is fat\n");
        return;
    }
    
    //决定32/64位
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        printf("only support 64\n");
        return;
    }
    
    kernel_exportSym = [NSMutableDictionary new];
    exportSym = [NSMutableDictionary new];
    NSMutableArray *tmp_symsname = [NSMutableArray new];
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)mh+sizeof(struct mach_header_64));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                uint32_t symoff = sym_cmd->symoff;
                uint32_t nsyms = sym_cmd->nsyms;
                uint32_t stroff = sym_cmd->stroff;
                uint32_t strsize = sym_cmd->strsize;
                
                for(int i =0;i<nsyms;i++){
                    //64位
                    struct nlist_64 *nn = (void*)((char*)mh+symoff+i*sizeof(struct nlist_64));
                    char *def_str = (char*)mh+(uint32_t)nn->n_un.n_strx + stroff;
                    [tmp_symsname addObject:[NSNumber numberWithUnsignedLongLong:(unsigned long)def_str]];
                    if(nn->n_value!=0){
                        [exportSym setObject:[NSString stringWithUTF8String:def_str] forKey:[NSNumber numberWithUnsignedLongLong:nn->n_value]];
                    }
                    
                }
            }
                break;
            case LC_DYSYMTAB:{
                
                struct dysymtab_command* dy_cmd = (struct dysymtab_command*)cmd;
                uint32_t extrefsymoff = dy_cmd->extreloff;
                uint32_t nextrel = dy_cmd->nextrel;
                
                for(int i=0;i<nextrel;i++){
                    struct relocation_info *relo_info = (void*)((char*)mh+extrefsymoff+i*sizeof(struct relocation_info));
                    if(relo_info->r_pcrel==0){
                        memset((char*)buf+relo_info->r_address,0xff,sizeof(void*));
                    }
                    else if(relo_info->r_extern){
                        char *def_str = (char*)[tmp_symsname[relo_info->r_symbolnum] unsignedLongLongValue];
                        [kernel_exportSym setObject:[NSString stringWithUTF8String:def_str] forKey:[NSNumber numberWithUnsignedLongLong:relo_info->r_address]];
                    }
                }
                //printf("patch %lu place for 0xff instead\n",(unsigned long)[tmp_symsname count]);
                
            }
                
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
}

#pragma mark imp:解析函数名从编译后的C++名字:
void getName_ClassAndFunc_of_Cpp(char *cpp_name,char *res[2]){
    
    if(!res){
        printf("getName_ClassAndFunc_of_Cpp NULL arg: char **res[2]\n");
        exit(1);
    }
    
    char *class_name=0,*func_name=0;
    
    NSString *orig_str = [NSString stringWithUTF8String:cpp_name];
    NSString *tmpStr;
    NSScanner *scanner = [NSScanner scannerWithString:orig_str];
    NSCharacterSet *num = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"];
    [scanner scanUpToCharactersFromSet:num intoString:NULL];
    
    [scanner scanCharactersFromSet:num intoString:&tmpStr];
    if(tmpStr){
        //检查长度过滤出类名,裁剪原字符串
        size_t used_len = [scanner scanLocation]+[tmpStr integerValue];
        if(used_len<=[orig_str length]){
            class_name = (char*)[[orig_str substringWithRange:NSMakeRange([scanner scanLocation],[tmpStr integerValue])] UTF8String];
            //printf("class_name: %s\n",class_name);
            orig_str = [orig_str substringWithRange:NSMakeRange(used_len,[orig_str length]-used_len)];
            scanner = [NSScanner scannerWithString:orig_str];
            [scanner scanUpToCharactersFromSet:num intoString:NULL];
        }
    }
    
    if(class_name){
        tmpStr = @"";
        [scanner scanCharactersFromSet:num intoString:&tmpStr];
        if(tmpStr){
            //检查长度过滤出函数名
            size_t used_len = [scanner scanLocation]+[tmpStr integerValue];
            if(used_len<=[orig_str length]){
                func_name = (char*)[[orig_str substringWithRange:NSMakeRange([scanner scanLocation],[tmpStr integerValue])] UTF8String];
                //printf("func_name: %s\n",func_name);
            }
        }
    }
    
    if(class_name&&func_name){
        res[0] = class_name;
        res[1] = func_name;
        return;
        //printf("class_name: %s\n",class_name);
        //printf("func_name: %s\n",func_name);
    }
    res[0] = 0;
    res[1] = 0;
}

#pragma mark imp://分析类的虚表
void ParseVtable(char *cn,uint64_t class_self,uint64_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff){
    //printf("lea:0x%llx %s\n",VMaddr,cn);
    
    //uint64_t __text_start = machoGetVMAddr(bin,"__TEXT","__text");
    //uint64_t __text_end = __text_start + machoGetSize(bin,"__TEXT","__text");
    
    uint64_t __const_start = machoGetVMAddr(bin,"__DATA","__const");
    
    //uint64_t *class_self = (uint64_t*)rdi;
    //uint64_t ip_addr = insn[j+2].address;
    //int64_t ip_offset = getMEMOPoffset(handle,&insn[j+1]);
    
    uint64_t vtable_start = 0;
    
    for(uint64_t cur_addr = VMaddr;cur_addr>=__const_start;){
        //这里是尝试在内存中找到自己类的地址的匹配
        uint64_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
        if(!memcmp(check_curAddr,&class_self,sizeof(class_self))){
            //找到啦~ じゃ保存起来
            vtable_start = cur_addr;
            
            //exit(1);
            break;
        }
        cur_addr = cur_addr - 0x8;
    }
    
    
    
    if(vtable_start){
        for(int i=0x0;i<0x28;i=i+0x8){
            uint64_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+i);
            if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                if(*check_curAddr==0x0){
                    vtable_start = vtable_start + i;
                    for(int z=0x0;z<0x28;z=z+0x8){
                        uint64_t *check_non_empty = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+z);
                        if(check_PointerAddrInVM((uint64_t)check_non_empty)){
                            if(*check_non_empty!=0){
                                vtable_start = vtable_start + z;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }
    //end of if(vtable_start)
    printf("vtable_start: 0x%llx\n",vtable_start);
    
    printf("\nvtable functions:\n");
    //尝试遍历虚表
    for(uint64_t cur_addr = vtable_start;;cur_addr+=0x8){
        uint64_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
        if(*check_curAddr==0){
            break;
        }
        if(*check_curAddr!=0xffffffffffffffff){
            char *res[2];
            char *func_n = (char*)[[exportSym objectForKey:[NSNumber numberWithUnsignedLongLong:*check_curAddr]] UTF8String];
            if(func_n){
               getName_ClassAndFunc_of_Cpp((char*)func_n,res);
               printf("%s_%s\n",res[0],res[1]);
            }
        }
    }
}

//传入每个KEXT的二进制,返回该KEXT的CFBundleID
#pragma mark imp:传入每个KEXT的二进制,返回该KEXT的CFBundleID
char *KextGetBundleID(void *bin){
    uint64_t dataSecStart = machoGetFileAddr(bin,"__DATA","__data");
    uint64_t dataSecSize = machoGetSize(bin,"__DATA","__data");
    
    //printf("\n__DATA is 0x%llx-0x%llx\n",dataSecStart,dataSecStart+dataSecSize);
    
    char mh_Magic[] = {'c','o','m','.'};
    uint64_t per_mh = (uint64_t)memmem(bin+dataSecStart,dataSecSize,mh_Magic,0x4);
    if(per_mh){
        return (char*)per_mh;
    }
    return "******WRONG_KEXT_NAME******";
}