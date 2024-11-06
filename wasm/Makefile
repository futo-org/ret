# source "/home/daniel/Pulled/emsdk/emsdk_env.sh"

CC := emcc
CPP := em++

CFLAGS := -fvisibility-inlines-hidden -Wall -W -Wno-unused-parameter -Wwrite-strings -Wcast-qual -Wno-missing-field-initializers -pedantic -Wno-long-long -Wno-maybe-uninitialized -Wdelete-non-virtual-dtor -Wno-comment
CFLAGS += -DLLVM_ENABLE_ARCH_AArch64 -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -Dkeystone_EXPORTS -fPIC -ffunction-sections -fdata-sections -DNDEBUG -fPIC -fvisibility=hidden

CFLAGS += -Ikeystone/build/llvm/keystone -Ikeystone/llvm/keystone -Ikeystone/build/llvm/include -Ikeystone/llvm/include
CFLAGS += -Ikeystone/llvm/keystone/../../include 
CFLAGS += -Ikeystone/llvm/keystone/../lib/Target/AArch64 -Ikeystone/llvm/keystone/../lib/Target/ARM -Ikeystone/llvm/keystone/../lib/Target/Hexagon
CFLAGS += -Ikeystone/llvm/keystone/../lib/Target/Mips -Ikeystone/llvm/keystone/../lib/Target/PowerPC -Ikeystone/llvm/keystone/../lib/Target/Sparc
CFLAGS += -Ikeystone/llvm/keystone/../lib/Target/SystemZ -Ikeystone/llvm/keystone/../lib/Target/X86 -Ikeystone/llvm/keystone/../lib/Target/RISCV

CPPFLAGS := $(CFLAGS) -std=c++11

KEYSTONE_FILES := keystone.o keystone/llvm/lib/MC/ConstantPools.o keystone/llvm/lib/MC/ELFObjectWriter.o keystone/llvm/lib/MC/MCAsmBackend.o keystone/llvm/lib/MC/MCAsmInfo.o keystone/llvm/lib/MC/MCAsmInfoCOFF.o keystone/llvm/lib/MC/MCAsmInfoDarwin.o keystone/llvm/lib/MC/MCAsmInfoELF.o keystone/llvm/lib/MC/MCAssembler.o keystone/llvm/lib/MC/MCCodeEmitter.o keystone/llvm/lib/MC/MCContext.o keystone/llvm/lib/MC/MCELFObjectTargetWriter.o keystone/llvm/lib/MC/MCELFStreamer.o keystone/llvm/lib/MC/MCExpr.o keystone/llvm/lib/MC/MCFragment.o keystone/llvm/lib/MC/MCInst.o keystone/llvm/lib/MC/MCInstrDesc.o keystone/llvm/lib/MC/MCLabel.o keystone/llvm/lib/MC/MCObjectFileInfo.o keystone/llvm/lib/MC/MCObjectStreamer.o keystone/llvm/lib/MC/MCObjectWriter.o keystone/llvm/lib/MC/MCParser/AsmLexer.o keystone/llvm/lib/MC/MCParser/AsmParser.o keystone/llvm/lib/MC/MCParser/COFFAsmParser.o keystone/llvm/lib/MC/MCParser/DarwinAsmParser.o keystone/llvm/lib/MC/MCParser/ELFAsmParser.o keystone/llvm/lib/MC/MCParser/MCAsmLexer.o keystone/llvm/lib/MC/MCParser/MCAsmParser.o keystone/llvm/lib/MC/MCParser/MCAsmParserExtension.o keystone/llvm/lib/MC/MCParser/MCTargetAsmParser.o keystone/llvm/lib/MC/MCRegisterInfo.o keystone/llvm/lib/MC/MCSection.o keystone/llvm/lib/MC/MCSectionCOFF.o keystone/llvm/lib/MC/MCSectionELF.o keystone/llvm/lib/MC/MCSectionMachO.o keystone/llvm/lib/MC/MCStreamer.o keystone/llvm/lib/MC/MCSubtargetInfo.o keystone/llvm/lib/MC/MCSymbol.o keystone/llvm/lib/MC/MCSymbolELF.o keystone/llvm/lib/MC/MCTargetOptions.o keystone/llvm/lib/MC/MCValue.o keystone/llvm/lib/MC/StringTableBuilder.o keystone/llvm/lib/MC/SubtargetFeature.o keystone/llvm/lib/Support/APFloat.o keystone/llvm/lib/Support/APInt.o keystone/llvm/lib/Support/APSInt.o keystone/llvm/lib/Support/ARMBuildAttrs.o keystone/llvm/lib/Support/ErrorHandling.o keystone/llvm/lib/Support/Hashing.o keystone/llvm/lib/Support/IntEqClasses.o keystone/llvm/lib/Support/LEB128.o keystone/llvm/lib/Support/Memory.o keystone/llvm/lib/Support/MemoryBuffer.o keystone/llvm/lib/Support/Path.o keystone/llvm/lib/Support/Regex.o keystone/llvm/lib/Support/ScaledNumber.o keystone/llvm/lib/Support/SmallPtrSet.o keystone/llvm/lib/Support/SmallVector.o keystone/llvm/lib/Support/SourceMgr.o keystone/llvm/lib/Support/StringExtras.o keystone/llvm/lib/Support/StringMap.o keystone/llvm/lib/Support/StringPool.o keystone/llvm/lib/Support/StringRef.o keystone/llvm/lib/Support/StringSaver.o keystone/llvm/lib/Support/TargetParser.o keystone/llvm/lib/Support/TargetRegistry.o keystone/llvm/lib/Support/Triple.o keystone/llvm/lib/Support/Twine.o keystone/llvm/lib/Support/raw_ostream.o keystone/llvm/lib/Support/regcomp.o keystone/llvm/lib/Support/regerror.o keystone/llvm/lib/Support/regexec.o keystone/llvm/lib/Support/regfree.o keystone/llvm/lib/Support/regstrlcpy.o keystone/llvm/lib/Target/AArch64/AsmParser/AArch64AsmParser.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64AsmBackend.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64ELFObjectWriter.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCAsmInfo.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCCodeEmitter.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCExpr.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64MCTargetDesc.o keystone/llvm/lib/Target/AArch64/MCTargetDesc/AArch64TargetStreamer.o keystone/llvm/lib/Target/AArch64/TargetInfo/AArch64TargetInfo.o keystone/llvm/lib/Target/AArch64/Utils/AArch64BaseInfo.o
KEYSTONE_FILES += keystone/llvm/lib/Target/ARM/TargetInfo/ARMTargetInfo.o
KEYSTONE_FILES += keystone/llvm/keystone/ks.o

# CMakeFiles/keystone.dir/ks.o CMakeFiles/keystone.dir/EVMMapping.o



DEMO_O := main.o $(KEYSTONE_FILES)
hello.html: shell.html $(DEMO_O)
	emcc $(DEMO_O) --shell-file shell.html -o hello.html

all: $(KEYSTONE_FILES)

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -o $@ -c $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

s:
	python3 -m http.server

clean:
	rm *.o *.wasm hello.html
