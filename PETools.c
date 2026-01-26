#include "PETools.h"


DWORD ReadPEFile(IN LPCSTR lpszFile, OUT LPVOID* ppFileBuffer) {
    FILE* pFile = NULL;
    DWORD fileSize = 0;

    // 打开文件并获取大小
    pFile = fopen(lpszFile, "rb");
    if (!pFile) {
        printf("无法打开文件\n");
        return 0;
    }
    fseek(pFile, 0, SEEK_END);
    fileSize = ftell(pFile);
    rewind(pFile);

    // 分配内存并读取文件内容
    *ppFileBuffer = (LPVOID)malloc(fileSize);
    if (!*ppFileBuffer) {
        printf("内存分配失败\n");
        fclose(pFile);
        return 0;
    }

    DWORD bytesRead = fread(*ppFileBuffer, 1, fileSize, pFile);
    fclose(pFile);
    printf("读取成功\n");
    return bytesRead;
}

VOID PrintPEHeaders(IN LPVOID pBuffer, IN LPCSTR bufferName)
{
    int i;
    if (!pBuffer) {
        printf("[错误] 缓冲区为空，无法解析PE结构\n");
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

    //判断是否是有效的MZ标志	
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[%s] 不是有效的MZ标志: 0x%04X (应为0x%04X)\n",
            bufferName, pDosHeader->e_magic, IMAGE_DOS_SIGNATURE);
        return;
    }

    //判断是否是有效的PE标志	
    if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        printf("[%s] 不是有效的PE标志\n", bufferName);
        return;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pBuffer + pDosHeader->e_lfanew);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

    // 计算PE文件实际大小（最后一个节的文件偏移 + 文件中的大小）
    PIMAGE_SECTION_HEADER pLastSection = &pSectionHeader[pPEHeader->NumberOfSections - 1];
    DWORD dwPEFileSize = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;

    printf("\n========================================\n");
    printf("[%s] PE文件结构详细信息\n", bufferName);
    printf("缓冲区地址: %p\n", pBuffer);
    printf("PE文件大小: 0x%08X (%d字节)\n", dwPEFileSize, dwPEFileSize);
    printf("========================================\n");

    //打印DOS头	
    printf("\n********************DOS头********************\n");
    printf("MZ标志(e_magic): 0x%04X %s\n", pDosHeader->e_magic,
        pDosHeader->e_magic == IMAGE_DOS_SIGNATURE ? "(有效)" : "(无效!)");
    printf("PE偏移(e_lfanew): 0x%08X (%d字节)\n", pDosHeader->e_lfanew, pDosHeader->e_lfanew);

    //打印NT头	
    printf("\n********************NT头********************\n");
    printf("NT签名(Signature): 0x%08X %s\n", pNTHeader->Signature,
        pNTHeader->Signature == IMAGE_NT_SIGNATURE ? "(有效PE)" : "(无效!)");

    printf("\n********************文件头(PE头)********************\n");
    printf("机器类型(Machine): 0x%04X ", pPEHeader->Machine);
    switch (pPEHeader->Machine) {
    case IMAGE_FILE_MACHINE_I386: printf("(x86)\n"); break;
    case 0x8664: printf("(x64)\n"); break;
    default: printf("(其他)\n");
    }
    printf("节的数量(NumberOfSections): %d\n", pPEHeader->NumberOfSections);
    printf("时间戳(TimeDateStamp): 0x%08X\n", pPEHeader->TimeDateStamp);
    printf("可选头大小(SizeOfOptionalHeader): 0x%04X (%d字节)\n",
        pPEHeader->SizeOfOptionalHeader, pPEHeader->SizeOfOptionalHeader);
    printf("文件特征(Characteristics): 0x%04X ", pPEHeader->Characteristics);
    if (pPEHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) printf("[可执行] ");
    if (pPEHeader->Characteristics & IMAGE_FILE_DLL) printf("[DLL] ");
    if (pPEHeader->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) printf("[大地址感知] ");
    printf("\n");

    //可选PE头	
    printf("\n********************可选头(OPTIONAL_HEADER)********************\n");
    printf("Magic标志: 0x%04X ", pOptionHeader->Magic);
    if (pOptionHeader->Magic == 0x10B) printf("(PE32)\n");
    else if (pOptionHeader->Magic == 0x20B) printf("(PE32+)\n");
    else printf("(未知)\n");

    printf("已初始化数据大小(SizeOfInitializedData): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfInitializedData, pOptionHeader->SizeOfInitializedData);
    printf("未初始化数据大小(SizeOfUninitializedData): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfUninitializedData, pOptionHeader->SizeOfUninitializedData);
    printf("入口点地址(AddressOfEntryPoint): 0x%08X\n", pOptionHeader->AddressOfEntryPoint);
    printf("代码基址(BaseOfCode): 0x%08X\n", pOptionHeader->BaseOfCode);
    printf("数据基址(BaseOfData): 0x%08X\n", pOptionHeader->BaseOfData);
    printf("镜像基址(ImageBase): 0x%08X\n", pOptionHeader->ImageBase);
    printf("内存对齐(SectionAlignment): 0x%08X (%d字节)\n",
        pOptionHeader->SectionAlignment, pOptionHeader->SectionAlignment);
    printf("文件对齐(FileAlignment): 0x%08X (%d字节)\n",
        pOptionHeader->FileAlignment, pOptionHeader->FileAlignment);
    printf("镜像大小(SizeOfImage): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfImage, pOptionHeader->SizeOfImage);
    printf("头部大小(SizeOfHeaders): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfHeaders, pOptionHeader->SizeOfHeaders);
    printf("校验和(CheckSum): 0x%08X\n", pOptionHeader->CheckSum);
    printf("子系统(Subsystem): 0x%04X ", pOptionHeader->Subsystem);
    if (pOptionHeader->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) printf("(GUI)\n");
    else if (pOptionHeader->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) printf("(控制台)\n");
    else printf("(其他)\n");

    printf("栈保留大小(SizeOfStackReserve): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfStackReserve, pOptionHeader->SizeOfStackReserve);
    printf("栈提交大小(SizeOfStackCommit): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfStackCommit, pOptionHeader->SizeOfStackCommit);
    printf("堆保留大小(SizeOfHeapReserve): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfHeapReserve, pOptionHeader->SizeOfHeapReserve);
    printf("堆提交大小(SizeOfHeapCommit): 0x%08X (%d字节)\n",
        pOptionHeader->SizeOfHeapCommit, pOptionHeader->SizeOfHeapCommit);
    printf("数据目录数量(NumberOfRvaAndSizes): %d\n", pOptionHeader->NumberOfRvaAndSizes);

    //打印节表
    printf("\n********************节表 (共%d个节)********************\n", pPEHeader->NumberOfSections);
    for (i = 0; i < pPEHeader->NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        printf("\n--- [节%d] %s ---\n", i + 1, sectionName);
        printf("  VirtualSize(内存中大小): 0x%08X (%d字节)\n",
            pSectionHeader[i].Misc.VirtualSize, pSectionHeader[i].Misc.VirtualSize);
        printf("  VirtualAddress(内存RVA): 0x%08X\n", pSectionHeader[i].VirtualAddress);
        printf("  SizeOfRawData(文件中大小): 0x%08X (%d字节)\n",
            pSectionHeader[i].SizeOfRawData, pSectionHeader[i].SizeOfRawData);
        printf("  PointerToRawData(文件偏移): 0x%08X\n", pSectionHeader[i].PointerToRawData);
        printf("  Characteristics(特征): 0x%08X ", pSectionHeader[i].Characteristics);

        // 解析特征标志
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) printf("[代码] ");
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("[已初始化数据] ");
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("[未初始化数据] ");
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) printf("[可执行] ");
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ) printf("[可读] ");
        if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) printf("[可写] ");
        printf("\n");

        // 计算并显示空闲空间
        DWORD freeSpace = 0;
        if (pSectionHeader[i].SizeOfRawData > pSectionHeader[i].Misc.VirtualSize) {
            freeSpace = pSectionHeader[i].SizeOfRawData - pSectionHeader[i].Misc.VirtualSize;
        }
        printf("  可用空间: %d字节 %s\n", freeSpace,
            freeSpace > 0 ? "(可注入代码)" : "(无空闲空间)");
    }

    // 显示节表后的可用空间
    printf("\n********************节表后空间********************\n");
    LPBYTE EndAddress = (LPBYTE)&pSectionHeader[pPEHeader->NumberOfSections];
    DWORD AvailableSpace = 0;
    for (i = 0; i < 200 && *(LPBYTE)EndAddress == 0; i++, EndAddress++) {
        AvailableSpace++;
    }
    printf("节表数组后的可用空间: %d字节 %s\n", AvailableSpace,
        AvailableSpace >= 40 ? "(足够添加新节)" : "(不足以添加新节，至少需要40字节)");

    printf("========================================\n");
    printf("[%s] PE结构解析完成\n", bufferName);
    printf("========================================\n\n");
}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* ppImageBuffer) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    PIMAGE_FILE_HEADER pFileHeader = &pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    DWORD SectionCount = 0;

    // 分配内存布局大小的缓冲区
    *ppImageBuffer = malloc(pOptionalHeader->SizeOfImage);
    memset(*ppImageBuffer, 0, pOptionalHeader->SizeOfImage);
    if (!*ppImageBuffer) {
        printf("内存分配失败\n");
        return 0;
    }
    // 验证DOS头
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("不是有效的MZ标志\n");
        return 0;
    }
    // 验证NT头
    pNTHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("不是有效的PE标志\n");
        return 0;
    }
    // 复制PE头部
    memcpy(*ppImageBuffer, pFileBuffer, pOptionalHeader->SizeOfHeaders);
    // 复制各个节到内存布局位置
    SectionCount = pFileHeader->NumberOfSections;
    DWORD i;
    for (i = 0; i < SectionCount; i++) {
        memcpy((LPVOID)((DWORD)*ppImageBuffer + pSectionHeader[i].VirtualAddress), (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
    }
    printf("PE文件在内存(FileBuffer)中成功拓展后复制到另一块内存（ImageBuffer）\n");
    return pOptionalHeader->SizeOfImage;
}



DWORD CopyImageBufferToFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID* ppNewBuffer) {
    // 重新解析ImageBuffer中的PE结构
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    PIMAGE_FILE_HEADER pFileHeader = &pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)&pSectionHeader[pFileHeader->NumberOfSections - 1];
    DWORD NewBufferSize;
    DWORD SectionCount;
    DWORD i;

    // 计算文件布局所需大小
    NewBufferSize = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
    *ppNewBuffer = malloc(NewBufferSize);
    if (!*ppNewBuffer) {
        printf("在把ImageBuffer中的PE文件压缩到FileBuffer中时，内存分配失败\n");
        return 0;
    }
    memset(*ppNewBuffer, 0, NewBufferSize);
    // 复制PE头部
    memcpy(*ppNewBuffer, pImageBuffer, pOptionalHeader->SizeOfHeaders);
    // 将各节从内存布局复制回文件布局
    SectionCount = pFileHeader->NumberOfSections;
    for (i = 0; i < SectionCount; i++) {
        memcpy(
            (LPVOID)((DWORD)*ppNewBuffer + pSectionHeader[i].PointerToRawData),
            (LPVOID)((DWORD)pImageBuffer + pSectionHeader[i].VirtualAddress),
            pSectionHeader[i].SizeOfRawData
        );
    }
    printf("ImageBuffer成功压缩到新缓冲区（NewBuffer）\n");
    return NewBufferSize;
}


DWORD MemoryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPCSTR lpszFile) {
    FILE* NewFile = NULL;
    // 创建新文件并写入数据
    NewFile = fopen(lpszFile, "wb");
    if (!NewFile) {
        printf("创建新文件失败\n");
        return 0;
    }
    DWORD FileWriteSize = fwrite(pMemBuffer, 1, size, NewFile);
    fclose(NewFile);
    printf("内存中的数据成功存入到地址:\n%s\n", lpszFile);
    return FileWriteSize;
}

int ValidatePEFile(IN LPVOID pFileBuffer) {
    if (!pFileBuffer) {
        printf("文件缓冲区为空\n");
        return 0;
    }

    // 验证DOS头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("不是有效的MZ标志\n");
        return 0;
    }

    // 验证NT头
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("不是有效的PE标志\n");
        return 0;
    }

    printf("PE文件验证成功\n");
    return 1;
}

DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva) {
    if (!pFileBuffer) {
        // printf("RVA转换FOA失败，缓冲区为NULL\n");
        return 0;
    }

    // 解析PE结构
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeaders + 4);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    DWORD dwSectionCount = pFileHeader->NumberOfSections;

    // 情况1: RVA在PE头部区域（在第一个节之前）
    if (dwRva < pSectionHeader[0].VirtualAddress) {
        //printf("RVA在PE头部区域，FOA = RVA，转换成功\n");
        return dwRva;
    }

    // 情况2: RVA在某个节区域内
    for (DWORD i = 0; i < dwSectionCount; i++) {
        DWORD dwSectionStart = pSectionHeader[i].VirtualAddress;
        DWORD dwSectionEnd = dwSectionStart + pSectionHeader[i].Misc.VirtualSize;

        if (dwRva >= dwSectionStart && dwRva < dwSectionEnd) {
            // 计算FOA = RVA - 节的RVA + 节的文件偏移
            DWORD dwFoa = dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
            //printf("RVA在节 [%s] 内,转换成功\n", pSectionHeader[i].Name);
            return dwFoa;
        }
    }

    // 情况3: RVA不在任何有效区域
   // printf("RVA转换FOA失败，RVA(0x%08X)不在任何有效节范围内\n", dwRva);
    return 0;
}

DWORD AddCode(IN PVOID pFileBuffer, IN PVOID pShellCode, IN  DWORD dwShellCodeSize, IN DWORD dwInjectRVA, IN DWORD dwInjectFileOffset) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &(pNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pTargetSection = &pSectionHeader[pFileHeader->NumberOfSections - 1];
    DWORD CodeBeginVA = pOptionalHeader->ImageBase + dwInjectRVA;

    // 将shellcode复制到目标节的末尾
    memcpy((LPVOID)((DWORD)pFileBuffer + dwInjectFileOffset), pShellCode, dwShellCodeSize);
    // 修改E8 call指令
    DWORD CallOffset = MessageBoxAAddr - (CodeBeginVA + 0xd);
    *(PDWORD)((DWORD)pFileBuffer + dwInjectFileOffset + 0x9) = CallOffset;
    // 修改E9 jmp指令
    DWORD JmpOffset = (pOptionalHeader->ImageBase + pOptionalHeader->AddressOfEntryPoint) - (CodeBeginVA + 0x12);
    *(PDWORD)((DWORD)pFileBuffer + dwInjectFileOffset + 0xe) = JmpOffset;
    // 更新入口点到shellcode位置 应该使用RVA而不是FOA
    printf("先前程序入口点OEP：%x\n", pOptionalHeader->AddressOfEntryPoint);
    pOptionalHeader->AddressOfEntryPoint = dwInjectRVA; // ✓ 使用RVA，不是FOA！
    printf("现已修改为：%x\n", pOptionalHeader->AddressOfEntryPoint);
    // 设置节为可执行      
    pTargetSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    // 更新节的虚拟大小
    pTargetSection->Misc.VirtualSize += dwShellCodeSize;

    printf("shellcode成功添加到节\n");
    printf("代码位置: CodeInFile=0x%08X RVA=0x%08X, VA=0x%08X\n", dwInjectFileOffset, dwInjectRVA, pOptionalHeader->ImageBase + dwInjectRVA);
    printf("Call偏移: 0x%08X, Jmp偏移: 0x%08X\n", CallOffset, JmpOffset);

    return 1;
}

DWORD AddSection(IN LPVOID pFileBuffer, IN DWORD OriginalFileSize, OUT LPVOID* ppNewFileBuffer, OUT LPDWORD pdwNewRVA, OUT LPDWORD pdwNewFileOffset) {
    LPBYTE EndAddress;
    DWORD AvailableSpace = 0;
    DWORD NewSectionSize = 0;
    char sectionName[8] = { 0 };
    int i;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &(pNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    // 检查节表数组后剩余空间
    EndAddress = (LPBYTE)&pSectionHeader[pFileHeader->NumberOfSections];
    for (i = 0; *(LPBYTE)EndAddress == 0; i++, EndAddress++) {
        AvailableSpace++;
    }

    printf("节表数组后剩余空间: %d 字节\n", AvailableSpace);
    if (AvailableSpace < 40) {
        printf("节表后没有足够的40字节空间添加新节\n");
        return 0;
    }

    // 获取用户输入
    DWORD newSectionVirtualSize = 0;
    printf("输入你要添加的新节的名称，包括.最多8字节，例如:.newsec\n");
    scanf("%8s", sectionName);
    printf("输入你需要的空间大小(BYTE)：\n");
    scanf("%d", &NewSectionSize);

   

    // 计算之前全文件对齐后的大小（标准向上对齐公式）
    DWORD alignedRawSize = (OriginalFileSize + pOptionalHeader->FileAlignment - 1) / pOptionalHeader->FileAlignment * pOptionalHeader->FileAlignment;

	//计算新增节所需的文件大小
    DWORD NewSectionFileSize = (NewSectionSize + pOptionalHeader->FileAlignment - 1) / pOptionalHeader->FileAlignment * pOptionalHeader->FileAlignment;
	DWORD NewSectionVirtualSize =(NewSectionSize + pOptionalHeader->SectionAlignment - 1) / pOptionalHeader->SectionAlignment * pOptionalHeader->SectionAlignment;

    // 先分配新缓冲区并复制旧内容，加上新节的空间

    *ppNewFileBuffer = calloc(alignedRawSize + NewSectionFileSize,1 );
    if (!*ppNewFileBuffer) {
        printf("内存分配失败\n");
        return 0;
    }
    memcpy(*ppNewFileBuffer, pFileBuffer, alignedRawSize);

    // 在新缓冲区上重新解析PE结构
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)*ppNewFileBuffer;
    PIMAGE_NT_HEADERS pNewNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = &(pNewNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pNewOptionalHeader = &(pNewNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNewOptionalHeader + pNewFileHeader->SizeOfOptionalHeader);

    // 获取新缓冲区中的节指针
    PIMAGE_SECTION_HEADER pNewSection = &pNewSectionHeader[pNewFileHeader->NumberOfSections];

    // 设置新节的属性
    memcpy(pNewSection->Name, sectionName, 8);
    pNewSection->Misc.VirtualSize = NewSectionSize;

	// VirtualAddress = 原文件Size（新节紧跟在镜像末尾）
    pNewSection->VirtualAddress = pOptionalHeader->SizeOfImage;
    pNewSection->SizeOfRawData = NewSectionFileSize;

    // PointerToRawData = 之前文件大小（新节紧跟在文件末尾）
    pNewSection->PointerToRawData = alignedRawSize;
    pNewSection->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;    // 可读可写可执行代码节

    // 更新PE头信息
    pNewOptionalHeader->SizeOfImage += NewSectionVirtualSize;
    pNewFileHeader->NumberOfSections += 1;

    printf("新节 %s 成功添加至FOA: 0x%08X 处\n", pNewSection->Name, pNewSection->PointerToRawData);
    printf("新PE FileBuffer地址为：%p\n", *ppNewFileBuffer);
    printf("新节大小: %d 字节\n新节节索引: %d\n", NewSectionFileSize, pNewFileHeader->NumberOfSections);

    if (pdwNewRVA) {
        *pdwNewRVA = (pNewSection->VirtualAddress);
    }
    if (pdwNewFileOffset) {
        *pdwNewFileOffset = (pNewSection->PointerToRawData);
    }

    printf("新节VirtualAddress: 0x%08X, PointerToRawData: 0x%08X\n",
        pNewSection->VirtualAddress, pNewSection->PointerToRawData);

    return alignedRawSize + NewSectionFileSize;
}

/*
 * 扩展最后一个节（“三明治”方案）
 * 这是“健壮”但“麻烦”的实现，它会“搬运”文件末尾的附加数据（Overlay/签名）
 */
DWORD ExpandLastSection(IN LPVOID pFileBuffer, IN DWORD OriginalFileSize, OUT LPVOID* ppNewFileBuffer, OUT LPDWORD pdwNewRVA, OUT LPDWORD pdwNewFileOffset) {
    DWORD dwExpandSize = 0; // 用户输入的"希望"扩展的大小
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &(pNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pLastSection = &pSectionHeader[pFileHeader->NumberOfSections - 1];

    printf("准备扩展最后一个节 :%s\n节索引:%d\n输入你需要增加的空间大小(字节):\n", pLastSection->Name, pFileHeader->NumberOfSections);
    scanf("%d", &dwExpandSize);

    // 1. 【保存旧值】
    DWORD oldVirtualSize = pLastSection->Misc.VirtualSize;
    DWORD oldRawSize = pLastSection->SizeOfRawData;
    // 【关键】"上半片面包"的末尾，也是我们的"插入点"
    DWORD oldLastSectionEndOffset = pLastSection->PointerToRawData + oldRawSize;

    // 2. 【计算新空间大小】
    // 我们必须在文件上扩展一个"文件对齐"后的大小
    DWORD alignedExpandSize = (dwExpandSize + pOptionalHeader->FileAlignment - 1) / pOptionalHeader->FileAlignment * pOptionalHeader->FileAlignment;

    // 3. 【计算"三明治"各部分】
    //    "下半片面包"（Overlay/签名）的大小
    DWORD overlaySize = OriginalFileSize - oldLastSectionEndOffset;
    if (overlaySize < 0) overlaySize = 0; // 健壮性检查

    // 4. 【分配新缓冲区】
    //    总大小 = 旧文件大小 + 我们新加的对齐后空间
    DWORD newBufferSize = OriginalFileSize + alignedExpandSize;
    *ppNewFileBuffer = (LPVOID)malloc(newBufferSize);
    if (!*ppNewFileBuffer) {
        printf("内存分配失败\n");
        return 0;
    }

    // 5. 【三明治 Step 1: 复制"上半片面包"】
    //    (从 0 复制到 最后一个节的【文件数据】末尾)
    memcpy(*ppNewFileBuffer, pFileBuffer, oldLastSectionEndOffset);

    // 6. 【三明治 Step 2: 粘贴你的"肉"(新空间)】
    //    (在"上半片面包"之后，清零)
    memset((LPVOID)((DWORD)*ppNewFileBuffer + oldLastSectionEndOffset), 0, alignedExpandSize);

    // 7. 【三明治 Step 3: 复制"下半片面包"(Overlay/签名)】
    //    (把旧文件中的 Overlay/签名，"搬运"到"肉"的后面)
    if (overlaySize > 0) {
        memcpy((LPVOID)((DWORD)*ppNewFileBuffer + oldLastSectionEndOffset + alignedExpandSize), // 目标
            (LPVOID)((DWORD)pFileBuffer + oldLastSectionEndOffset),               // 源
            overlaySize);
    }

    // 8. 在【新缓冲区】上重新解析 PE 头
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)*ppNewFileBuffer;
    PIMAGE_NT_HEADERS pNewNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = &(pNewNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pNewOptionalHeader = &(pNewNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNewOptionalHeader + pNewFileHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pNewLastSection = &pNewSectionHeader[pNewFileHeader->NumberOfSections - 1];

    // 9. 【更新最后一个节的头】
    //    我们【不】依赖 oldVirtualSize。
    //    我们的"健壮"逻辑是：新的虚拟大小 = 旧的文件大小 + 扩展大小
    //    (这会"填满"任何"间隙"，并加上新空间)
    DWORD newVirtualSize = oldRawSize + dwExpandSize;
    pNewLastSection->Misc.VirtualSize = newVirtualSize;
    //    新的文件大小 = 旧的文件大小 + 对齐后的扩展大小
    pNewLastSection->SizeOfRawData = oldRawSize + alignedExpandSize;

    // 10. 【健壮地】更新 SizeOfImage (重新计算)
    //     (使用我们【新】的、健壮的 newVirtualSize)
    pNewOptionalHeader->SizeOfImage = (pNewLastSection->VirtualAddress + newVirtualSize + pNewOptionalHeader->SectionAlignment - 1)
        / pNewOptionalHeader->SectionAlignment * pNewOptionalHeader->SectionAlignment;

    printf("节扩展完成：VirtualSize: %d -> %d, SizeOfRawData: %d -> %d\n",
        oldVirtualSize, pNewLastSection->Misc.VirtualSize, oldRawSize, pNewLastSection->SizeOfRawData);// oldVirtualSize 只是用来"对比显示"

    // 11. 【返回你新空间的起始地址】(Bug 修正！)
    //     我们【不】依赖 oldVirtualSize。
    //     我们的 RVA 【必须】对应我们的 FOA。
    //     FOA = ... + oldRawSize (即 oldLastSectionEndOffset)
    //     RVA = ... + oldRawSize (这是 FOA 对应的 RVA)
    *pdwNewRVA = pNewLastSection->VirtualAddress + oldRawSize;
    *pdwNewFileOffset = oldLastSectionEndOffset;
    printf("扩展起始地址：RVA: 0x%08X, FOA: 0%08X\n",
        *pdwNewRVA, *pdwNewFileOffset);

    return newBufferSize;
}

DWORD MergeSections(IN LPVOID pImageBuffer, OUT LPVOID* ppNewFileBuffer) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);

    DWORD ImageSize = pOptionalHeader->SizeOfImage;

    *ppNewFileBuffer = calloc(1, ImageSize);
    memcpy(*ppNewFileBuffer, pImageBuffer, ImageSize);

    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)*ppNewFileBuffer;
    PIMAGE_NT_HEADERS pNewNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = &(pNewNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pNewOptionalHeader = &(pNewNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNewOptionalHeader + pNewFileHeader->SizeOfOptionalHeader);

    DWORD SectionCount = pNewFileHeader->NumberOfSections;
    if (SectionCount < 2) {
        printf("节合并失败，节数量不足\n");
        return 0;
    }
    PIMAGE_SECTION_HEADER pFirstSection = &pNewSectionHeader[0];
    PIMAGE_SECTION_HEADER pLastSection = &pNewSectionHeader[SectionCount - 1];

    //合并属性标志
    DWORD i;
    for (i = 1; i < SectionCount; i++) {
        pFirstSection->Characteristics |= pNewSectionHeader[i].Characteristics;
    }
    //更新第一个节的属性
    pFirstSection->Misc.VirtualSize = ImageSize - pFirstSection->VirtualAddress;
    pFirstSection->SizeOfRawData = pFirstSection->Misc.VirtualSize;
    //设置节数量为1
    pNewFileHeader->NumberOfSections = 1;

    //给被合并的节表清零
    for (i = 1; i < SectionCount; i++) {
        memset(&pNewSectionHeader[i], 0, sizeof(IMAGE_SECTION_HEADER));
    }
    return ImageSize;
}

DWORD Align(IN DWORD data, IN DWORD alignment) {
    return (data + alignment - 1) / alignment * alignment;
}

void PrintDataDirectory(IN LPVOID pBuffer) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = &(pNTHeaders->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    printf("\n********************数据目录(Data Directory)********************\n");
    const char* tableNames[] = {
        "导出表(Export Table)",
        "导入表(Import Table)",
        "资源表(Resource Table)",
        "异常信息表(Exception Table)",
        "安全证书表(Certificate Table)",
        "重定位表(Base Relocation Table)",
        "调试信息表(Debug Table)",
        "版权所有表(Architecture - specific data)",
        "全局指针表(Global Pointer)",
        "TLS 表(Thread Local Storage)",
        "加载配置表(Load Config Table)",
        "绑定导入表(Bound Import)",
        "IAT 表(Import Address Table)",
        "延迟导入表(Delay Import Descriptor)",
        "COM 信息表(CLI header)",
        "保留未使用"
    };
    DWORD num = pOptionalHeader->NumberOfRvaAndSizes;
    DWORD i;
    for (i = 0; i < num; i++) {
        printf("%s:\n        RVA: 0x%X,       Size: %d\n\n", tableNames[i], pOptionalHeader->DataDirectory[i].VirtualAddress, pOptionalHeader->DataDirectory[i].Size);
    }

}

void PrintExportTable(IN LPVOID pBuffer) {
    if (!pBuffer) {
        printf("缓冲区为空\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pExportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (pExportDirRVA == 0) {
        printf("没有导出表\n");
        return;
    }
    DWORD ExportDirFOA = RvaToFileOffset(pBuffer, pExportDirRVA) + (DWORD)pBuffer;

    PDWORD pNameRVA = (PDWORD)(ExportDirFOA + 0xc);
    PDWORD pBase = (PDWORD)(ExportDirFOA + 0x10);
    PDWORD pNumberOfFunctions = (PDWORD)(ExportDirFOA + 0x14);
    PDWORD pNumberOfNames = (PDWORD)(ExportDirFOA + 0x18);
    PDWORD pAOF = (PDWORD)(ExportDirFOA + 0x1c);
    PDWORD pAON = (PDWORD)(ExportDirFOA + 0x20);
    PDWORD pAOO = (PDWORD)(ExportDirFOA + 0x24);

    PCSTR pNameFOA = (PCSTR)(RvaToFileOffset(pBuffer, *pNameRVA) + (DWORD)pBuffer);
    PDWORD pAOFf = (PDWORD)(RvaToFileOffset(pBuffer, *pAOF) + (DWORD)pBuffer);
    PDWORD pAONf = (PDWORD)(RvaToFileOffset(pBuffer, *pAON) + (DWORD)pBuffer);
    PWORD pAOOf = (PWORD)(RvaToFileOffset(pBuffer, *pAOO) + (DWORD)pBuffer);

    printf("Characteristics - 已废弃，通常为0\n");
    printf("%x\n", *(PDWORD)ExportDirFOA);
    printf("TimeDateStamp          - 创建时间戳(1970年以来的秒数)\n");
    printf("%x\n", *(PDWORD)(ExportDirFOA + 4));
    printf("MajorVersion           - 主版本号(通常为0)\n");
    printf("%x\n", *(PWORD)(ExportDirFOA + 8));
    printf("MinorVersion           - 次版本号(通常为0)\n");
    printf("%x\n", *(PWORD)(ExportDirFOA + 0xa));
    printf("Name                   - 模块名称字符串的RVA与名称\n");
    printf("%x--- %s\n", *pNameRVA, pNameFOA);
    printf("Base                   - 导出函数的起始序号\n");
    printf("%x\n", *pBase);
    printf("NumberOfFunctions      - 所有导出函数的总数\n");
    printf("%d\n", *pNumberOfFunctions);
    printf("NumberOfNames          - 有名称的导出函数数量\n");
    printf("%d\n", *pNumberOfNames);
    printf("AddressOfFunctions     - 指向函数地址表(RVA数组)的RVA\n");
    printf("%x\n", *pAOF);
    printf("AddressOfNames         - 指向函数名称表(RVA数组)的RVA\n");
    printf("%x\n", *pAON);
    printf("AddressOfNameOrdinals  - 指向函数序号表(WORD数组)的RVA\n");
    printf("%x\n", *pAOO);
    printf("\n********************导出函数列表(总览)********************\n");

    DWORD i;
    for (i = 0; i < *pNumberOfFunctions; i++) {
        DWORD FunctionRVA = pAOFf[i];
        PCSTR FunctionName = "-";
        if (!FunctionRVA) continue; // 跳过空地址
        printf("函数导出序号: %d ", *pBase + i);
        printf("RVA: 0x%X ", FunctionRVA);
        // 查找函数名称
        DWORD j;
        for (j = 0; j < *pNumberOfFunctions; j++) {
            if (pAOOf[j] == i) {
                FunctionName = (PCSTR)(RvaToFileOffset(pBuffer, pAONf[i]) + (DWORD)pBuffer);
                break;
            }
        }
        printf("函数名称: %s\n", FunctionName);
    }

    printf("\n********************函数地址表********************\n");
    for (i = 0; i < *pNumberOfFunctions; i++) {
        printf("RVA: 0x%X\n", pAOFf[i]);
    }
    printf("\n********************函数名称表********************\n");
    for (i = 0; i < *pNumberOfNames; i++) {
        printf("名称: %s\n", (PCSTR)(RvaToFileOffset(pBuffer, pAONf[i]) + (DWORD)pBuffer));
    }
    printf("\n********************函数序号表********************\n");
    for (i = 0; i < *pNumberOfNames; i++) {
        printf("序号: %d\n", pAOOf[i]);
    }
}

DWORD GetFunctionAddrByName(IN LPVOID pBuffer, IN PCSTR FunctionName) {
    if (!pBuffer) {
        printf("缓冲区为空\n");
        return 0;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pExportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (pExportDirRVA == 0) {
        printf("没有导出表\n");
        return 0;
    }
    DWORD ExportDirFOA = RvaToFileOffset(pBuffer, pExportDirRVA) + (DWORD)pBuffer;

    PDWORD pNameRVA = (PDWORD)(ExportDirFOA + 0xc);
    PDWORD pBase = (PDWORD)(ExportDirFOA + 0x10);
    PDWORD pNumberOfFunctions = (PDWORD)(ExportDirFOA + 0x14);
    PDWORD pNumberOfNames = (PDWORD)(ExportDirFOA + 0x18);
    PDWORD pAOF = (PDWORD)(ExportDirFOA + 0x1c);
    PDWORD pAON = (PDWORD)(ExportDirFOA + 0x20);
    PDWORD pAOO = (PDWORD)(ExportDirFOA + 0x24);

    PCSTR pNameFOA = (PCSTR)(RvaToFileOffset(pBuffer, *pNameRVA) + (DWORD)pBuffer);
    PDWORD pAOFf = (PDWORD)(RvaToFileOffset(pBuffer, *pAOF) + (DWORD)pBuffer);
    PDWORD pAONf = (PDWORD)(RvaToFileOffset(pBuffer, *pAON) + (DWORD)pBuffer);
    PWORD pAOOf = (PWORD)(RvaToFileOffset(pBuffer, *pAOO) + (DWORD)pBuffer);

    int j;
    PCSTR funcName;
    for (j = 0; j < *pNumberOfNames; j++) {
        funcName = (PCSTR)(RvaToFileOffset(pBuffer, pAONf[j]) + (DWORD)pBuffer);
        if (strcmp(funcName, FunctionName) == 0) {
            return pAOFf[pAOOf[j]];
            break;
        }
    }
    return 0;

}

DWORD GetFunctionAddrByOrdinals(IN LPVOID pBuffer, IN WORD Ordinal) {
    if (!pBuffer) {
        printf("缓冲区为空\n");
        return 0;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pExportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (pExportDirRVA == 0) {
        printf("没有导出表\n");
        return 0;
    }
    DWORD ExportDirFOA = RvaToFileOffset(pBuffer, pExportDirRVA) + (DWORD)pBuffer;

    PDWORD pNameRVA = (PDWORD)(ExportDirFOA + 0xc);
    PDWORD pBase = (PDWORD)(ExportDirFOA + 0x10);
    PDWORD pNumberOfFunctions = (PDWORD)(ExportDirFOA + 0x14);
    PDWORD pNumberOfNames = (PDWORD)(ExportDirFOA + 0x18);
    PDWORD pAOF = (PDWORD)(ExportDirFOA + 0x1c);
    PDWORD pAON = (PDWORD)(ExportDirFOA + 0x20);
    PDWORD pAOO = (PDWORD)(ExportDirFOA + 0x24);

    PCSTR pNameFOA = (PCSTR)(RvaToFileOffset(pBuffer, *pNameRVA) + (DWORD)pBuffer);
    PDWORD pAOFf = (PDWORD)(RvaToFileOffset(pBuffer, *pAOF) + (DWORD)pBuffer);
    PDWORD pAONf = (PDWORD)(RvaToFileOffset(pBuffer, *pAON) + (DWORD)pBuffer);
    PWORD pAOOf = (PWORD)(RvaToFileOffset(pBuffer, *pAOO) + (DWORD)pBuffer);

    int j;
    for (j = 0; j < *pNumberOfNames; j++) {
        if (pAOOf[j] == Ordinal) {
            return pAOFf[pAOOf[j]];
            break;
        }
    }
    return 0;
}

void MoveExportTable(IN LPVOID pFileBuffer, IN DWORD FileSize, IN LPVOID* ppNewBuffer, IN DWORD NewExportRVA, IN DWORD NewExportFOA) {
    if (!pFileBuffer) {
        printf("缓冲区为空\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pExportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (pExportDirRVA == 0) {
        printf("没有导出表\n");
        return;
    }

    //复制到新缓冲区
    *ppNewBuffer = (PVOID)calloc(FileSize, 1);
    memcpy(*ppNewBuffer, pFileBuffer, FileSize);

    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)*ppNewBuffer;
    PIMAGE_NT_HEADERS pNewNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pNewOptionalHeader = &(pNewNTHeaders->OptionalHeader);

    DWORD ExportDirFOA = RvaToFileOffset(*ppNewBuffer, pExportDirRVA) + (DWORD)*ppNewBuffer;

    PDWORD pNameRVA = (PDWORD)(ExportDirFOA + 0xc);
    PDWORD pBase = (PDWORD)(ExportDirFOA + 0x10);
    PDWORD pNumberOfFunctions = (PDWORD)(ExportDirFOA + 0x14);
    PDWORD pNumberOfNames = (PDWORD)(ExportDirFOA + 0x18);
    PDWORD pAOFrva = (PDWORD)(ExportDirFOA + 0x1c);
    PDWORD pAONrva = (PDWORD)(ExportDirFOA + 0x20);
    PDWORD pAOOrva = (PDWORD)(ExportDirFOA + 0x24);

    PCSTR pNameFOA = (PCSTR)(RvaToFileOffset(*ppNewBuffer, *pNameRVA) + (DWORD)*ppNewBuffer);
    PDWORD pAOFf = (PDWORD)(RvaToFileOffset(*ppNewBuffer, *pAOFrva) + (DWORD)*ppNewBuffer);
    PDWORD pAONf = (PDWORD)(RvaToFileOffset(*ppNewBuffer, *pAONrva) + (DWORD)*ppNewBuffer);
    PWORD pAOOf = (PWORD)(RvaToFileOffset(*ppNewBuffer, *pAOOrva) + (DWORD)*ppNewBuffer);

    PBYTE pTargetAddr = (PBYTE)((DWORD)*ppNewBuffer + NewExportFOA);
    //复制EAT数据到新位置
    DWORD EATSize = (*pNumberOfFunctions) * sizeof(DWORD);
    memcpy(pTargetAddr, pAOFf, EATSize);
    *pAOFrva = NewExportRVA;            //更新导出表EAT表RVA
    pTargetAddr += EATSize;

    //复制EOT数据到新位置
    DWORD EOTSize = (*pNumberOfNames) * sizeof(WORD);
    memcpy(pTargetAddr, pAOOf, EOTSize);
    *pAOOrva = NewExportRVA + EATSize;          //更新导出表EOT表RVA
    pTargetAddr += EOTSize;

    //复制ENT数据到新位置
    DWORD ENTSize = (*pNumberOfNames) * sizeof(DWORD);
    memcpy(pTargetAddr, pAONf, ENTSize);
    *pAONrva = NewExportRVA + EATSize + EOTSize;        //更新导出表ENT表RVA
    pAONf = (PDWORD)pTargetAddr;            //更新函数名称表指针
    pTargetAddr += ENTSize;

    //复制模块名称字符串到新位置和修改对应ENT表
    int i;
    for (i = 0; i < *pNumberOfNames; i++) {

        PCSTR funcName = (PCSTR)(RvaToFileOffset(*ppNewBuffer, pAONf[i]) + (DWORD)*ppNewBuffer);      //RVA转换，得到函数名字符串的地址
        memcpy(pTargetAddr, funcName, strlen(funcName) + 1); //包含结束符
        pAONf[i] = NewExportRVA + (DWORD)(pTargetAddr - (DWORD)*ppNewBuffer - NewExportFOA);
        pTargetAddr += strlen(funcName) + 1;
    }

    //复制导出表到新位置，复制的是已更新后的，所以后面不用调整三小表RVA了
    memcpy(pTargetAddr, (PVOID)ExportDirFOA, sizeof(IMAGE_EXPORT_DIRECTORY));
    PIMAGE_EXPORT_DIRECTORY pNewExportDir = (PIMAGE_EXPORT_DIRECTORY)pTargetAddr;
    pTargetAddr += sizeof(IMAGE_EXPORT_DIRECTORY);

    //更新导出表目录项索引
    pNewOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)pNewExportDir - ((DWORD)*ppNewBuffer + NewExportFOA) + NewExportRVA;
    pNewOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = (DWORD)pTargetAddr - ((DWORD)*ppNewBuffer + NewExportFOA);

}


void PrintRelocTable(IN LPVOID pFileBuffer) {
    if (!pFileBuffer) {
        printf("缓冲区为空，无法打印重定位表\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pRelocDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    if (pRelocDirRVA == 0) {
        printf("没有重定位表\n");
        return;
    }
    DWORD RelocDirFOA = RvaToFileOffset(pFileBuffer, pRelocDirRVA) + (DWORD)pFileBuffer;

    printf("重定位表信息:\n");
    DWORD Index = 1;
    while (1) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)RelocDirFOA;
        if (pReloc->SizeOfBlock == 0) break;

        printf("表项条目 %d :      FOA:%X  RVA: %X, Size: %d\n", Index, RelocDirFOA - (DWORD)pFileBuffer, pReloc->VirtualAddress, pReloc->SizeOfBlock);
        DWORD EntryCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pRelocEntry = (WORD*)(RelocDirFOA + sizeof(IMAGE_BASE_RELOCATION));
        DWORD i;
        for (i = 0; i < EntryCount; i++) {
            if (pRelocEntry[i] & 0x3000) printf("    重定位条目 %d:   FOA :%X  偏移: 0x%X  RVA: 0x%X\n", i, (DWORD)&pRelocEntry[i] - (DWORD)pFileBuffer, 0xFFF & pRelocEntry[i], pReloc->VirtualAddress + (0xFFF & pRelocEntry[i]));
            else break;
        }
        RelocDirFOA += pReloc->SizeOfBlock;
        Index++;
    }
}



void MoveRelocTable(IN LPVOID pFileBuffer, IN DWORD FileSize, IN LPVOID* ppNewBuffer, IN DWORD NewRelocRVA, IN DWORD NewRelocFOA) {
    if (!pFileBuffer) {
        printf("缓冲区为空\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pRelocDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    if (pRelocDirRVA == 0) {
        printf("没有重定位表\n");
        return;
    }
    *ppNewBuffer = (PVOID)calloc(1, FileSize);

    if (!*ppNewBuffer) {
        printf("内存分配失败\n");
        return;
    }
    memcpy(*ppNewBuffer, pFileBuffer, FileSize);
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)*ppNewBuffer;
    PIMAGE_NT_HEADERS pNewNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pNewOptionalHeader = &(pNewNTHeaders->OptionalHeader);
    DWORD RelocDirFOA = RvaToFileOffset(*ppNewBuffer, pRelocDirRVA) + (DWORD)*ppNewBuffer;
    DWORD RelocDirTarget = RelocDirFOA;
    DWORD RelocDirSize = 0;

    while (1) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)RelocDirTarget;
        if (pReloc->SizeOfBlock == 0) break;
		RelocDirSize += pReloc->SizeOfBlock;
        RelocDirTarget += pReloc->SizeOfBlock;
    }
	RelocDirSize += sizeof(IMAGE_BASE_RELOCATION); //加上最后一个空表项的大小

	memcpy((PBYTE)((DWORD)*ppNewBuffer + NewRelocFOA), (PVOID)RelocDirFOA, RelocDirSize);

    //更新重定位表目录项索引
    pNewOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NewRelocRVA;
	pNewOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = RelocDirSize;

  
}

DWORD ChangeImageBase(IN LPVOID pBuffer, IN DWORD NewImageBase) {
    if (!pBuffer) {
        printf("缓冲区为空，失败\n");
        return 0;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);

    DWORD OldImageBase = pNTHeaders->OptionalHeader.ImageBase;
    pNTHeaders->OptionalHeader.ImageBase = NewImageBase;

    printf("ImageBase修改: 0x%08X -> 0x%08X\n", OldImageBase, NewImageBase);
    return OldImageBase;
}

void FixRelocEntries(IN LPVOID pFileBuffer ,IN DWORD OldImageBase ,IN DWORD NewImageBase, IN DWORD NewRelocRVA, IN DWORD NewRelocFOA) {
	int Delta = (int)NewImageBase - (int)OldImageBase;
    if (!pFileBuffer) {
        printf("缓冲区为空，失败\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD pRelocDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD RelocDirFOA = RvaToFileOffset(pFileBuffer, pRelocDirRVA) + (DWORD)pFileBuffer;
    DWORD RelocDirTarget = RelocDirFOA;
    DWORD RelocDirSize = 0;

    while (1) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)RelocDirTarget;
        if (pReloc->SizeOfBlock == 0) break;
        DWORD EntryCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pRelocEntry = (WORD*)(RelocDirTarget + sizeof(IMAGE_BASE_RELOCATION));
		DWORD i;
        for (i = 0; i < EntryCount; i++) {
            if (pRelocEntry[i] & 0x3000) {
                 PDWORD pFun = (PDWORD)(RvaToFileOffset(pFileBuffer,(pRelocEntry[i] & 0x0FFF) + pReloc->VirtualAddress) + (DWORD)pFileBuffer ); 
				 *pFun += Delta;
            }
            else break;
        }

		RelocDirTarget += pReloc->SizeOfBlock;
    }
	printf("重定位表修正完成\n");

}

void PrintImportTable(IN LPVOID pFileBuffer) {
    if (!pFileBuffer) {
        printf("缓冲区为空，失败\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);

    DWORD ImportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ImportDirRVA == 0) {
        printf("没有导入表\n");
        return;
    }
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer, ImportDirRVA) + (DWORD)pFileBuffer);
    
    

    DWORD IndexDLL;
    //遍历DLL
    for (IndexDLL = 1; pImportDesc->Name != 0 && pImportDesc->FirstThunk != 0; pImportDesc++, IndexDLL++) {
        
		PCSTR DllName = (PCSTR)(RvaToFileOffset(pFileBuffer, pImportDesc->Name) + (DWORD)pFileBuffer);
        printf("*************************************\n");
		printf("(%d) DLL名称: %s\n", IndexDLL, DllName);

		printf("----------------INT项----------------\n");
		//遍历INT
        DWORD IndexINT;
        PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(RvaToFileOffset(pFileBuffer, pImportDesc->OriginalFirstThunk) + (DWORD)pFileBuffer);
        for (IndexINT = 1; pINT->u1.AddressOfData != 0; pINT++, IndexINT++) {
            
            if (pINT->u1.AddressOfData & 0x80000000) {     //按序号导入
                printf("    %d、导入序号: 0x%x\n", IndexINT,pINT->u1.Ordinal & 0x7fffffff);
            }else {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer, pINT->u1.AddressOfData) + (DWORD)pFileBuffer);         //按名称导入
                printf("    %d、导入HIT: 0x%x  函数名称: %s \n", IndexINT,pImportByName->Hint, pImportByName->Name);
            }
        }
        printf("----------------IAT项----------------\n");
        DWORD IndexIAT;
        PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(RvaToFileOffset(pFileBuffer, pImportDesc->FirstThunk) + (DWORD)pFileBuffer);
        //遍历IAT
        for (IndexIAT = 1; pIAT->u1.AddressOfData != 0; pIAT++, IndexIAT++) {
            if (pIAT->u1.AddressOfData & 0x80000000) {     //按序号导入
                printf("    %d、导入序号: 0x%x\n", IndexIAT, pIAT->u1.Ordinal & 0x0fff);
            }
            else {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer, pIAT->u1.AddressOfData) + (DWORD)pFileBuffer);         //按名称导入
                printf("    %d、导入HIT: 0x%x  函数名称: %s \n", IndexIAT, pImportByName->Hint, pImportByName->Name);
            }
        }
		 
    }
}

void PrintBoundImportTable(IN LPVOID pFileBuffer) {
    if (!pFileBuffer) {
        printf("缓冲区为空，失败\n");
        return;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);
    DWORD BoundImportRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
    if (BoundImportRVA == 0) {
        printf("没有绑定导入表\n");
        return;
	}
    DWORD BoundImportBase = RvaToFileOffset(pFileBuffer, BoundImportRVA) + (DWORD)pFileBuffer;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR pImportBoundDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(BoundImportBase);
	DWORD IndexDLL = 1;
    while (pImportBoundDesc->OffsetModuleName != 0) {

        PCSTR DllName = (PCSTR)(BoundImportBase + pImportBoundDesc->OffsetModuleName);
        printf("(%d) 绑定DLL名称:       %s\n", IndexDLL, DllName);
        time_t Time = (time_t)pImportBoundDesc->TimeDateStamp;
        printf("    时间戳与时间:      0x%x - %s", pImportBoundDesc->TimeDateStamp, ctime(&Time));
		DWORD DefCount = pImportBoundDesc->NumberOfModuleForwarderRefs;
        printf("    模块向前引用数:    %d\n\n", DefCount);
        if (DefCount > 0) {
			PIMAGE_BOUND_FORWARDER_REF pForwarderRef = (PIMAGE_BOUND_FORWARDER_REF)((DWORD)pImportBoundDesc + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
			printf("    向前引用列表:\n");
            DWORD i;
            for ( i = 0; i < DefCount; i++) {
                printf("    %d. %s ", i + 1, (PCSTR)(BoundImportBase + pForwarderRef->OffsetModuleName));
                Time = (time_t)pImportBoundDesc->TimeDateStamp;
                printf("        :     0x%x - %s\n", pForwarderRef->TimeDateStamp, ctime(&Time));
                pForwarderRef++;
            }
            pImportBoundDesc += DefCount+1, IndexDLL++;
        }else {
            pImportBoundDesc++, IndexDLL++;

        }
    }

}

void DllImportInjection(IN PVOID pFileBuffer, IN DWORD NewImportRVA) {
    if (!pFileBuffer) {
        printf("缓冲区为空，失败\n");
        return ;
    }
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &(pNTHeaders->OptionalHeader);

    DWORD ImportDirRVA = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ImportDirRVA == 0) {
        printf("没有导入表,请用其他注入方法\n");
        return ;
    }
    PIMAGE_IMPORT_DESCRIPTOR pImportDec = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer, ImportDirRVA) + (DWORD)pFileBuffer);
    PIMAGE_IMPORT_DESCRIPTOR pBaseAddr = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, NewImportRVA) );
    PIMAGE_IMPORT_DESCRIPTOR pTargetDesc = pImportDec;

  
    DWORD OldDLLNum;
	//遍历DLL数量
    for (OldDLLNum = 0; pTargetDesc->Name != 0 && pTargetDesc->FirstThunk != 0; pTargetDesc++, OldDLLNum++); 

    char DLLName[MAX_PATH];
	printf("请输入要注入的DLL名称(含后缀): ");
	scanf("%259s", DLLName);
	char FunctionName[MAX_PATH];
	printf("请输入要注入的函数名称: ");
	scanf("%259s", FunctionName);

    DWORD TotalSize = (strlen(DLLName) + 1)       // DLL 名称字符串长度　＋ 1
        + (2 + strlen(FunctionName) + 1)    // 导入函数名结构(IMAGE_IMPORT_BY_NAME)：2字节(Hint) + 函数名长度 + 1
		+ sizeof(IMAGE_THUNK_DATA) * 4      // INT与IAT表空间，包含结束项
        + (OldDLLNum + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // 原DLL 描述符表长度　＋　新增的DLL 描述符表长度＋ 结束描述符表长度

    PBYTE pCountAddr = (PBYTE)pBaseAddr;
	DWORD AvaliableSize;
    for (AvaliableSize = 0; *pCountAddr == 0 && AvaliableSize < TotalSize; AvaliableSize++, pCountAddr++);
	if (AvaliableSize < TotalSize) {
        printf("指定位置空间不足，无法注入\n");
        return ;
    }

    memcpy(pBaseAddr, pImportDec, (OldDLLNum + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pTargetDesc = pBaseAddr + OldDLLNum; //1、定位到新增的DLL描述符表位置
    PBYTE pCursor = (PBYTE)(pTargetDesc + 2);

	PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)pCursor;
	pCursor += sizeof(IMAGE_THUNK_DATA) * 2; // 2、INT表空间，包含结束项

	PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)pCursor;
	pCursor += sizeof(IMAGE_THUNK_DATA) * 2; // 3、IAT表空间，包含结束项

	PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)pCursor; // 4、函数名结构空间
	pImportByName->Hint = 0;
	strcpy((char*)pImportByName->Name, FunctionName);

	pIAT->u1.AddressOfData = pINT->u1.AddressOfData = NewImportRVA + ((DWORD)pImportByName - (DWORD)pBaseAddr); // 更新INT和IAT表项

	pCursor += sizeof(WORD) + strlen(FunctionName) + 1; // 5、存放DLL名称字符串
	strcpy((char*)pCursor, DLLName);

	pTargetDesc->Name = NewImportRVA + ((DWORD)pCursor - (DWORD)pBaseAddr); // 更新DLL名称RVA
	pTargetDesc->OriginalFirstThunk = NewImportRVA + ((DWORD)pINT - (DWORD)pBaseAddr); // 更新INT表RVA
	pTargetDesc->FirstThunk = NewImportRVA + ((DWORD)pIAT - (DWORD)pBaseAddr); // 更新IAT表RVA

    pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NewImportRVA;
	pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (OldDLLNum + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    printf("DLL注入完成\n");
}

/*DWORD QueryCodeSection(IN PVOID pImageBuffer, OUT PVOID* ppCodeRVA) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (DWORD)pDosHeader);
    PIMAGE_FILE_HEADER pFileHeader = &pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeaders->OptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	DWORD SectionNum = pFileHeader->NumberOfSections;
	DWORD i;
    for(i = 0 ; i < SectionNum; i++)
	{
		if (pSectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE)
		{
			*ppCodeRVA = (PVOID)(pSectionHeader[i].VirtualAddress + (DWORD)pImageBuffer);
			return pSectionHeader[i].Misc.VirtualSize;
		}
	}
	return 0;
}
*/