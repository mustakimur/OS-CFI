#include "llvm/IR/CallSite.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Bitcode/BitcodeReader.h> /// for isBitcode
#include <llvm/IRReader/IRReader.h>     /// for isIRFile

#include <fstream>
#include <map>
#include <set>
#include <vector>

using namespace llvm;

static cl::opt<std::string> dirPath("DIR_PATH",
                                    cl::desc("give the program path directory"),
                                    cl::value_desc("directory path"));

typedef std::vector<unsigned long> contextList;
typedef std::vector<unsigned long>::iterator contextListIt;
typedef std::pair<unsigned long, contextList> ctxToTargetPair;
typedef std::set<ctxToTargetPair> ctxToTargetSet;
typedef std::set<ctxToTargetPair>::iterator ctxToTargetSetIt;
typedef std::map<unsigned long, ctxToTargetSet> pointToECMap;
typedef std::map<unsigned long, ctxToTargetSet>::iterator pointToECMapIt;
typedef std::map<unsigned long, int> pointToType;
typedef std::map<unsigned long, int>::iterator pointToTypeIt;

typedef enum TARGET_TYPE {
  V_OS = 1,
  V_CI = 2,
  P_OS_CTX = 3,
  P_OS = 4,
  P_CS1 = 5,
  P_CS2 = 6,
  P_CS3 = 7,
  P_CI = 8
} targetType;

class INSTCFG : public ModulePass {
private:
  void replaceGLBUsage(GlobalVariable *New, GlobalVariable *Old) {
    std::set<User *> users;
    for (Value::user_iterator u = Old->user_begin(); u != Old->user_end();
         ++u) {
      User *user = *u;
      users.insert(user);
    }
    for (std::set<User *>::iterator u = users.begin(); u != users.end(); ++u) {
      User *user = *u;
      if (isa<GetElementPtrInst>(user)) {
        GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user);
        gep->setSourceElementType(New->getValueType());
        for (unsigned I = 0, E = user->getNumOperands(); I < E; ++I) {
          if (user->getOperand(I) == Old) {
            user->setOperand(I, New);
          }
        }
      }
    }
    New->setSection(Old->getSection());
  }

public:
  static char ID;
  INSTCFG() : ModulePass(ID) {
    unsigned long ty, p, t, s1, s2, s3;
    std::ifstream initcallfd;
    std::string path;
    if (dirPath[0] == '~') {
      dirPath.replace(0, 1, std::getenv("HOME"));
    }

    path = dirPath + "/ciCFG.bin";
    initcallfd.open(path.c_str());
    if (initcallfd.is_open()) {
      while (initcallfd >> ty >> p >> t) {
        contextList ctx;
        ctxToTargetPair target;
        target = std::make_pair(t, ctx);
        mapPEC[p].insert(target);
        if (ty == 1)
          mapPD[p] = P_CI;
        else
          mapPD[p] = V_CI;
      }
    }
    initcallfd.close();

    path = dirPath + "/cs1CFG.bin";
    initcallfd.open(path.c_str());
    if (initcallfd.is_open()) {
      while (initcallfd >> ty >> p >> s1 >> t) {
        contextList ctx;
        ctx.push_back(s1);
        ctxToTargetPair target;
        target = std::make_pair(t, ctx);
        mapPEC[p].insert(target);
        mapPD[p] = P_CS1;
      }
    }
    initcallfd.close();

    path = dirPath + "/cs2CFG.bin";
    initcallfd.open(path.c_str());
    if (initcallfd.is_open()) {
      while (initcallfd >> ty >> p >> s1 >> s2 >> t) {
        contextList ctx;
        ctx.push_back(s1);
        ctx.push_back(s2);
        ctxToTargetPair target;
        target = std::make_pair(t, ctx);
        mapPEC[p].insert(target);
        mapPD[p] = P_CS2;
      }
    }
    initcallfd.close();

    path = dirPath + "/cs3CFG.bin";
    initcallfd.open(path.c_str());
    if (initcallfd.is_open()) {
      while (initcallfd >> ty >> p >> s1 >> s2 >> s3 >> t) {
        contextList ctx;
        ctx.push_back(s1);
        ctx.push_back(s2);
        ctx.push_back(s3);
        ctxToTargetPair target;
        target = std::make_pair(t, ctx);
        mapPEC[p].insert(target);
        mapPD[p] = P_CS3;
      }
    }
    initcallfd.close();

    path = dirPath + "/osCFG.bin";
    initcallfd.open(path.c_str());
    if (initcallfd.is_open()) {
      while (initcallfd >> ty >> p >> s1 >> s2 >> t) {
        contextList ctx;
        ctx.push_back(s1);
        ctx.push_back(s2);
        originList.push_back(s1);
        ctxToTargetPair target;
        target = std::make_pair(t, ctx);
        mapPEC[p].insert(target);
        if (ty == 1 && s2 != 0)
          mapPD[p] = P_OS_CTX;
        else if (ty == 1 && s2 == 0)
          mapPD[p] = P_OS;
        else
          mapPD[p] = V_OS;
      }
    }
    initcallfd.close();
  }

  virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
    // declare your dependencies here.
    /// do not intend to change the IR in this pass,
    au.setPreservesAll();
  }

  bool runOnModule(Module &M) override {
    PointerType *int32PtTy = Type::getInt32PtrTy(M.getContext());
    IntegerType *int32Ty = Type::getInt32Ty(M.getContext());
    std::vector<Constant *> list_P_CI, list_P_CS1, list_P_CS2, list_P_CS3,
        list_P_OS, list_V_CI, list_V_OS;

    for (pointToECMapIt pIt = mapPEC.begin(); pIt != mapPEC.end(); ++pIt) {
      Constant *cPoint_t = ConstantInt::get(int32Ty, pIt->first, false);
      Constant *cPoint = ConstantFolder().CreateIntToPtr(cPoint_t, int32PtTy);
      for (ctxToTargetSetIt tIt = pIt->second.begin(); tIt != pIt->second.end();
           ++tIt) {
        Constant *cTarget_t = ConstantInt::get(int32Ty, tIt->first, false);
        Constant *cTarget =
            ConstantFolder().CreateIntToPtr(cTarget_t, int32PtTy);
        if (mapPD[pIt->first] == P_CI) {
          list_P_CI.push_back(cPoint);
          list_P_CI.push_back(cTarget);
        } else if (mapPD[pIt->first] == V_CI) {
          list_V_CI.push_back(cPoint);
          list_V_CI.push_back(cTarget);
        } else if (mapPD[pIt->first] == P_CS1) {
          list_P_CS1.push_back(cPoint);
          list_P_CS1.push_back(cTarget);
          for (auto cIt = (tIt->second).begin(); cIt != (tIt->second).end();
               ++cIt) {
            Constant *cContext_t = ConstantInt::get(int32Ty, *cIt, false);
            Constant *cContext =
                ConstantFolder().CreateIntToPtr(cContext_t, int32PtTy);
            list_P_CS1.push_back(cContext);
          }
        } else if (mapPD[pIt->first] == P_CS2) {
          list_P_CS2.push_back(cPoint);
          list_P_CS2.push_back(cTarget);
          for (auto cIt = (tIt->second).begin(); cIt != (tIt->second).end();
               ++cIt) {
            Constant *cContext_t = ConstantInt::get(int32Ty, *cIt, false);
            Constant *cContext =
                ConstantFolder().CreateIntToPtr(cContext_t, int32PtTy);
            list_P_CS2.push_back(cContext);
          }
        } else if (mapPD[pIt->first] == P_CS3) {
          list_P_CS3.push_back(cPoint);
          list_P_CS3.push_back(cTarget);
          for (auto cIt = (tIt->second).begin(); cIt != (tIt->second).end();
               ++cIt) {
            Constant *cContext_t = ConstantInt::get(int32Ty, *cIt, false);
            Constant *cContext =
                ConstantFolder().CreateIntToPtr(cContext_t, int32PtTy);
            list_P_CS3.push_back(cContext);
          }
        } else if (mapPD[pIt->first] == P_OS) {
          list_P_OS.push_back(cPoint);
          list_P_OS.push_back(cTarget);
          for (auto cIt = (tIt->second).begin(); cIt != (tIt->second).end();
               ++cIt) {
            Constant *cContext_t = ConstantInt::get(int32Ty, *cIt, false);
            Constant *cContext =
                ConstantFolder().CreateIntToPtr(cContext_t, int32PtTy);
            list_P_OS.push_back(cContext);
          }
        } else if (mapPD[pIt->first] == V_OS) {
          list_V_OS.push_back(cPoint);
          list_V_OS.push_back(cTarget);
          for (auto cIt = (tIt->second).begin(); cIt != (tIt->second).end();
               ++cIt) {
            Constant *cContext_t = ConstantInt::get(int32Ty, *cIt, false);
            Constant *cContext =
                ConstantFolder().CreateIntToPtr(cContext_t, int32PtTy);
            list_V_OS.push_back(cContext);
          }
        }
      }
    }

    // PCI
    ArrayRef<Constant *> blockArrayPCI(list_P_CI);
    // create the constant type and array
    ArrayType *pArrTyPCI = ArrayType::get(int32PtTy, list_P_CI.size());
    Constant *blockItemsPCI = ConstantArray::get(pArrTyPCI, blockArrayPCI);

    GlobalVariable *gCFG_oldPCI = M.getGlobalVariable("PCALL_D0");
    gCFG_oldPCI->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataPCI = new GlobalVariable(
        M, blockItemsPCI->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsPCI, "PCALL_D0");

    replaceGLBUsage(gvar_cfg_dataPCI, gCFG_oldPCI);

    Constant *cfgLenPCI = ConstantInt::get(int32Ty, list_P_CI.size(), false);
    GlobalVariable *gCFG_lenPCI = M.getGlobalVariable("PCALL_D0_C");
    gCFG_lenPCI->setInitializer(cfgLenPCI);

    // V_CI
    ArrayRef<Constant *> blockArrayVCI(list_P_CI);
    // create the constant type and array
    ArrayType *pArrTyVCI = ArrayType::get(int32PtTy, list_P_CI.size());
    Constant *blockItemsVCI = ConstantArray::get(pArrTyVCI, blockArrayVCI);

    GlobalVariable *gCFG_oldVCI = M.getGlobalVariable("STATIC_TABLE");
    gCFG_oldVCI->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataVCI = new GlobalVariable(
        M, blockItemsVCI->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsVCI, "STATIC_TABLE");

    replaceGLBUsage(gvar_cfg_dataVCI, gCFG_oldVCI);

    Constant *cfgLenVCI = ConstantInt::get(int32Ty, list_P_CI.size(), false);
    GlobalVariable *gCFG_lenVCI = M.getGlobalVariable("STATIC_TABLE_LENGTH");
    gCFG_lenVCI->setInitializer(cfgLenVCI);

    // PCS1
    ArrayRef<Constant *> blockArrayPCS1(list_P_CS1);
    ArrayType *pArrTyPCS1 = ArrayType::get(int32PtTy, list_P_CS1.size());
    Constant *blockItemsPCS1 = ConstantArray::get(pArrTyPCS1, blockArrayPCS1);

    GlobalVariable *gCFG_PCS1 = M.getGlobalVariable("PCALL_D1");
    gCFG_PCS1->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataPCS1 = new GlobalVariable(
        M, blockItemsPCS1->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsPCS1, "PCALL_D1");

    replaceGLBUsage(gvar_cfg_dataPCS1, gCFG_PCS1);

    Constant *cfgLenPCS1 = ConstantInt::get(int32Ty, list_P_CS1.size(), false);
    GlobalVariable *gCFG_lenPCS1 = M.getGlobalVariable("PCALL_D1_C");
    gCFG_lenPCS1->setInitializer(cfgLenPCS1);

    // PCS2
    ArrayRef<Constant *> blockArrayPCS2(list_P_CS2);
    ArrayType *pArrTyPCS2 = ArrayType::get(int32PtTy, list_P_CS2.size());
    Constant *blockItemsPCS2 = ConstantArray::get(pArrTyPCS2, blockArrayPCS2);

    GlobalVariable *gCFG_oldPCS2 = M.getGlobalVariable("PCALL_D2");
    gCFG_oldPCS2->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataPCS2 = new GlobalVariable(
        M, blockItemsPCS2->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsPCS2, "PCALL_D2");

    replaceGLBUsage(gvar_cfg_dataPCS2, gCFG_oldPCS2);

    Constant *cfgLenPCS2 = ConstantInt::get(int32Ty, list_P_CS2.size(), false);
    GlobalVariable *gCFG_lenPCS2 = M.getGlobalVariable("PCALL_D2_C");
    gCFG_lenPCS2->setInitializer(cfgLenPCS2);

    // PCS3
    ArrayRef<Constant *> blockArrayPCS3(list_P_CS3);
    ArrayType *pArrTyPCS3 = ArrayType::get(int32PtTy, list_P_CS3.size());
    Constant *blockItemsPCS3 = ConstantArray::get(pArrTyPCS3, blockArrayPCS3);

    GlobalVariable *gCFG_oldPCS3 = M.getGlobalVariable("PCALL_D3");
    gCFG_oldPCS3->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataPCS3 = new GlobalVariable(
        M, blockItemsPCS3->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsPCS3, "PCALL_D3");

    replaceGLBUsage(gvar_cfg_dataPCS3, gCFG_oldPCS3);

    Constant *cfgLenPCS3 = ConstantInt::get(int32Ty, list_P_CS3.size(), false);
    GlobalVariable *gCFG_lenPCS3 = M.getGlobalVariable("PCALL_D3_C");
    gCFG_lenPCS3->setInitializer(cfgLenPCS3);

    // V_OS
    ArrayRef<Constant *> blockArrayVOS(list_V_OS);
    ArrayType *pArrTyVOS = ArrayType::get(int32PtTy, list_V_OS.size());
    Constant *blockItemsVOS = ConstantArray::get(pArrTyVOS, blockArrayVOS);

    GlobalVariable *gCFG_oldVOS = M.getGlobalVariable("VCALL_OSCFI");
    gCFG_oldVOS->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataVOS = new GlobalVariable(
        M, blockItemsVOS->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsVOS, "VCALL_OSCFI");

    replaceGLBUsage(gvar_cfg_dataVOS, gCFG_oldVOS);

    Constant *cfgLenVOS = ConstantInt::get(int32Ty, list_V_OS.size(), false);
    GlobalVariable *gCFG_lenVOS = M.getGlobalVariable("VCALL_OSCFI_C");
    gCFG_lenVOS->setInitializer(cfgLenVOS);

    // P_OS
    ArrayRef<Constant *> blockArrayPOS(list_P_OS);
    ArrayType *pArrTyPOS = ArrayType::get(int32PtTy, list_P_OS.size());
    Constant *blockItemsPOS = ConstantArray::get(pArrTyPOS, blockArrayPOS);

    GlobalVariable *gCFG_oldPOS = M.getGlobalVariable("PCALL_OSCFI");
    gCFG_oldPOS->setDSOLocal(false);

    GlobalVariable *gvar_cfg_dataPOS = new GlobalVariable(
        M, blockItemsPOS->getType(), true, GlobalValue::ExternalLinkage,
        blockItemsPOS, "PCALL_OSCFI");

    replaceGLBUsage(gvar_cfg_dataPOS, gCFG_oldPOS);

    Constant *cfgLenPOS = ConstantInt::get(int32Ty, list_P_OS.size(), false);
    GlobalVariable *gCFG_lenPOS = M.getGlobalVariable("PCALL_OSCFI_C");
    gCFG_lenPOS->setInitializer(cfgLenPOS);

    Function *U_MPX = M.getFunction("update_mpx_table");

    Function *P_REF = M.getFunction("pcall_reference_monitor");
    Function *V_REF = M.getFunction("vcall_reference_monitor");

    Function *OSCFI_P_CTX_REF =
        M.getFunction("oscfi_pcall_ctx_reference_monitor");
    Function *OSCFI_P_REF = M.getFunction("oscfi_pcall_reference_monitor");
    Function *OSCFI_V_REF = M.getFunction("oscfi_vcall_reference_monitor");

    Function *CI_P_REF = M.getFunction("oscfi_pcall_reference_monitor_d0");
    Function *CI_V_REF = M.getFunction("static_vcall_reference_monitor");

    Function *CS_D1_REF = M.getFunction("oscfi_pcall_reference_monitor_d1");
    Function *CS_D2_REF = M.getFunction("oscfi_pcall_reference_monitor_d2");
    Function *CS_D3_REF = M.getFunction("oscfi_pcall_reference_monitor_d3");

    unsigned long callID, originID;
    IntegerType *int64Ty = Type::getInt64Ty(M.getContext());
    for (Function &Fn : M) {
      for (BasicBlock &BB : Fn) {
        for (Instruction &Inst : BB) {
          Instruction *inst = &Inst;
          if (isa<CallInst>(inst)) {
            CallInst *call = dyn_cast<CallInst>(inst);
            if (call->getCalledFunction() &&
                (call->getCalledFunction() == P_REF ||
                 call->getCalledFunction() == V_REF)) {
              Value *idValue = call->getArgOperand(0);
              if (isa<ConstantInt>(idValue)) {
                ConstantInt *cint = dyn_cast<ConstantInt>(idValue);
                callID = cint->getZExtValue();

                if (mapPD.find(callID) != mapPD.end()) {
                  int d = mapPD[callID];
                  if (d == P_CI) {
                    call->setCalledFunction(CI_P_REF);
                  } else if (d == V_CI) {
                    call->setCalledFunction(CI_V_REF);
                  } else if (d == P_OS_CTX) {
                    call->setCalledFunction(OSCFI_P_CTX_REF);
                  } else if (d == P_OS) {
                    call->setCalledFunction(OSCFI_P_REF);
                  } else if (d == V_OS) {
                    call->setCalledFunction(OSCFI_V_REF);
                  } else if (d == P_CS1) {
                    call->setCalledFunction(CS_D1_REF);
                  } else if (d == P_CS2) {
                    call->setCalledFunction(CS_D2_REF);
                  } else if (d == P_CS3) {
                    call->setCalledFunction(CS_D3_REF);
                  }
                }
              }
            } else if (call->getCalledFunction() &&
                       call->getCalledFunction() == U_MPX) {
              Value *idValue = call->getArgOperand(2);
              if (isa<ConstantInt>(idValue)) {
                ConstantInt *cint = dyn_cast<ConstantInt>(idValue);
                originID = cint->getZExtValue();
                if (find(originList.begin(), originList.end(), originID) ==
                    originList.end()) {
                  Constant *rm_id = ConstantInt::get(int64Ty, 0, false);
                  call->setArgOperand(2, rm_id);
                }
              }
            }
          }
        }
      }
    }

    return true; // must return true if module is modified
  }

private:
  pointToECMap mapPEC;
  pointToType mapPD;
  contextList originList;
};

char INSTCFG::ID = 0;
static RegisterPass<INSTCFG> Trans("llvm-inst-cfg",
                                   "LLVM Instrumentation of dCFG and cCFG");
