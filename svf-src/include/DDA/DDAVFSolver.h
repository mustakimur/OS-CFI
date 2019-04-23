/*
 * Origin-sensitive Control Flow Integrity
 * Author: Mustakimur R. Khandaker (mrk15e@my.fsu.edu)
 * Affliation: Florida State University
 */
#ifndef VALUEFLOWDDA_H_
#define VALUEFLOWDDA_H_

#include "DDA/DDAStat.h"
#include "MSSA/SVFGBuilder.h"
#include "Util/SCC.h"
#include "WPA/Andersen.h"
#include <algorithm>

#define DEBUG_SOLVER 0
#define DEBUG_DETAILS 0

/*!
 * Value-Flow Based Demand-Driven Points-to Analysis
 */
template <class CVar, class CPtSet, class DPIm> class DDAVFSolver {
  friend class DDAStat;

public:
  typedef SCCDetection<SVFG *> SVFGSCC;
  typedef SCCDetection<PTACallGraph *> CallGraphSCC;
  typedef PTACallGraphEdge::CallInstSet CallInstSet;
  typedef PAG::CallSiteSet CallSiteSet;
  typedef std::set<DPIm> DPTItemSet;
  typedef std::map<DPIm, CPtSet> DPImToCPtSetMap;
  typedef std::map<DPIm, CVar> DPMToCVarMap;
  typedef std::map<DPIm, DPIm> DPMToDPMMap;
  typedef llvm::DenseMap<NodeID, DPTItemSet> LocToDPMVecMap;
  typedef std::set<const SVFGEdge *> ConstSVFGEdgeSet;
  typedef SVFGEdge::SVFGEdgeSetTy SVFGEdgeSet;
  typedef std::map<const SVFGNode *, DPTItemSet> StoreToPMSetMap;
  // [OS-CFI] general typedef
  typedef std::set<const llvm::Instruction *> InstructionSet;
  typedef std::set<const llvm::Instruction *>::iterator InstructionSetIt;
  typedef std::map<NodeID, const StoreSVFGNode *> NodeToStoreMap;
  typedef std::map<NodeID, const StoreSVFGNode *>::iterator NodeToStoreMapIt;
  // [OS-CFI] Origin sensitive typedef
  typedef std::map<NodeID, InstructionSet> TargetToOriginContextMap;
  // [OS-CFI] set of origin sensitive tuples maps to sink
  typedef std::map<NodeID, OriginSensitiveTupleSet *>
      SinkToOriginSensitiveTupleSetMap;
  typedef std::map<NodeID, OriginSensitiveTupleSet *>::iterator
      SinkToOriginSensitiveTupleSetMapIt;
  // [OS-CFI] set of call stack maps to sink
  typedef std::map<NodeID, CallStackSet *> SinkToCallStackMap;
  typedef std::map<NodeID, CallStackSet *>::iterator SinkToCallStackMapIt;

  /// Constructor
  DDAVFSolver()
      : outOfBudgetQuery(false), _pag(NULL), _svfg(NULL), _ander(NULL),
        _callGraph(NULL), _callGraphSCC(NULL), _svfgSCC(NULL), ddaStat(NULL) {}
  /// Destructor
  virtual ~DDAVFSolver() {
    if (_ander != NULL) {
      // AndersenWaveDiff::releaseAndersenWaveDiff();
      _ander = NULL;
    }

    if (_svfg != NULL) {
      // DDASVFGBuilder::releaseDDASVFG();
      _svfg = NULL;
    }

    if (_svfgSCC != NULL)
      delete _svfgSCC;
    _svfgSCC = NULL;

    _callGraph = NULL;
    _callGraphSCC = NULL;
  }
  /// Return candidate pointers for DDA
  inline NodeBS &getCandidateQueries() { return candidateQueries; }
  /// Given CVar and location (SVFGNode) return a new DPItem
  virtual inline DPIm getDPIm(const CVar &var, const SVFGNode *loc) const {
    DPIm dpm(var, loc);
    return dpm;
  }
  /// Union pts
  virtual bool unionDDAPts(CPtSet &pts, const CPtSet &targetPts) {
    return (pts |= targetPts);
  }
  /// Add pts
  virtual void addDDAPts(CPtSet &pts, const CVar &var) { pts.set(var); }
  /// Return SVFG
  inline SVFG *getSVFG() const { return _svfg; }
  /// Return SVFGSCC
  inline SVFGSCC *getSVFGSCC() const { return _svfgSCC; }
  // Dump cptsSet
  inline void dumpCPtSet(const CPtSet &cpts) const {
    llvm::outs() << "{";
    for (typename CPtSet::iterator it = cpts.begin(), eit = cpts.end();
         it != eit; ++it) {
      llvm::outs() << (*it) << " ";
    }
    llvm::outs() << "}\n";
  }

  // [OS-CFI] getCurCandidate(): return the current candidate node id
  virtual inline NodeID getCurCandidate() { return curCandidate; }

  // [OS-CFI] setCurCandidate(): set current candidate node
  virtual inline void setCurCandidate(NodeID id) {
    curCandidate = id;
    OriginSensitiveTupleSet *setOSen = new OriginSensitiveTupleSet();
    CallStackSet *setCSen = new CallStackSet();
    mapSOrgSenTupSet[curCandidate] = setOSen;
    mapCSSen[curCandidate] = setCSen;
  }

  // [OS-CFI] dumpCallStack(): print the current call-stack
  void dumpCallStack() {
    if (DEBUG_SOLVER) {
      llvm::outs() << "***************[OS-CFI] CALL STACK ("
                   << setCallStack.size() << ") [OS-CFI]********************\n";
      CallSwitchPairStack curStack(setCallStack);
      while (!curStack.empty()) {
        if (curStack.top().second)
          llvm::outs() << curStack.top().first << " => "
                       << *(curStack.top().second) << "\n";
        curStack.pop();
      }
      llvm::outs()
          << "**********************************************************"
             "***************\n";
    }
  }

  // [OS-CFI] clearCallStack(): clear the current call-stack
  void clearCallStack() {
    while (!setCallStack.empty()) {
      setCallStack.pop();
    }
  }

  // [OS-CFI] isOriginCtxInCallStack(): return true if checked origin context is
  // in the current call-stack
  bool isOriginCtxInCallStack(const llvm::Instruction *originCtx) {
    const llvm::Instruction *topInst = nullptr;
    CallSwitchPairStack curStack(setCallStack);
    while (!curStack.empty()) {
      topInst = curStack.top().second;
      curStack.pop();
    }
    if (topInst == originCtx) {
      return true;
    }
    return false;
  }

  // [OS-CFI] createCSEntry(): will create a new call-site sensitive CFG entry
  // using the current call-stack but in reverse order
  void createCSEntry(NodeID id) {
    CallSwitchPairStack curStack(setCallStack);
    CallSwitchPairStack tmp;
    while (!curStack.empty()) {
      tmp.push(curStack.top());
      curStack.pop();
    }
    mapCSSen[getCurCandidate()]->insert(std::make_pair(id, tmp));
  }

  // [OS-CFI] handleOSensitivity(): it maps origin information for a candidate
  void handleOSensitivity(const DPIm &dpm, const AddrSVFGNode *addr,
                          bool flag) {
    NodeID srcID = addr->getPAGSrcNodeID();

    if (mapNodeStore.count(dpm.getLoc()->getId()) > 0) {
      mapNodeStore[srcID] = mapNodeStore[dpm.getLoc()->getId()];
      if (DEBUG_SOLVER) {
        llvm::outs() << "[OS-CFI] mapNodeStore[" << srcID << "] = mapNodeStore["
                     << dpm.getLoc()->getId() << "]\n";
        if (DEBUG_DETAILS) {
          llvm::outs() << "[OS-CFI] Store Instruction ";
          llvm::outs() << *(mapNodeStore[dpm.getLoc()->getId()]->getInst())
                       << "\n";
        }
      }

      if (mapTOrgCtx.count(dpm.getLoc()->getId()) > 0) {
        for (InstructionSetIt it = mapTOrgCtx[dpm.getLoc()->getId()].begin();
             it != mapTOrgCtx[dpm.getLoc()->getId()].end(); it++) {
          if (*it != nullptr) {
            if (DEBUG_SOLVER) {
              llvm::outs() << "[OS-CFI] mapSOrgSenTupSet[" << getCurCandidate()
                           << "] <= <" << srcID << ", mapNodeStore["
                           << dpm.getLoc()->getId() << "], " << **it << "]"
                           << ">\n";
            }
            mapSOrgSenTupSet[getCurCandidate()]->insert(std::make_tuple(
                srcID, mapNodeStore[dpm.getLoc()->getId()], *it));
            if (flag && isOriginCtxInCallStack(*it)) {
              createCSEntry(srcID);
            }
          } else {
            mapSOrgSenTupSet[getCurCandidate()]->insert(std::make_tuple(
                srcID, mapNodeStore[dpm.getLoc()->getId()], nullptr));
            if (DEBUG_SOLVER) {
              llvm::outs() << "[OS-CFI] mapSOrgSenTupSet[" << getCurCandidate()
                           << "] <= <" << srcID << ", "
                           << "mapNodeStore[" << dpm.getLoc()->getId() << "], "
                           << "nullptr]"
                           << ">\n";
            }
          }
        }
      } else {
        mapSOrgSenTupSet[getCurCandidate()]->insert(std::make_tuple(
            srcID, mapNodeStore[dpm.getLoc()->getId()], nullptr));
        if (DEBUG_SOLVER) {
          llvm::outs() << "[OS-CFI] mapSOrgSenTupSet[" << getCurCandidate()
                       << "] <= <" << srcID << ", mapNodeStore["
                       << dpm.getLoc()->getId() << "], "
                       << "nullptr]"
                       << ">\n";
        }
      }
    } else {
      if (DEBUG_SOLVER) {
        llvm::outs() << "[OS-CFI] uninitialized address-taken at "
                     << dpm.getLoc()->getId() << "\n";
      }
    }
  }

  /// Compute points-to
  virtual const CPtSet &findPT(const DPIm &dpm) {

    if (isbkVisited(dpm)) {
      const CPtSet &cpts = getCachedPointsTo(dpm);
      DBOUT(DDDA, llvm::outs() << "\t already backward visited dpm: ");
      DBOUT(DDDA, dpm.dump());
      DBOUT(DDDA, llvm::outs() << "\t return points-to: ");
      DBOUT(DDDA, dumpCPtSet(cpts));
      // [OS-CFI] ToDo
      const SVFGNode *node = dpm.getLoc();
      if (llvm::isa<AddrSVFGNode>(node)) {
        handleOSensitivity(dpm, llvm::cast<AddrSVFGNode>(node), true);
      }
      return cpts;
    }

    DBOUT(DDDA, llvm::outs() << "\t backward visit dpm: ");
    DBOUT(DDDA, dpm.dump());
    markbkVisited(dpm);
    addDpmToLoc(dpm);

    if (testOutOfBudget(dpm) == false) {

      CPtSet pts;
      handleSingleStatement(dpm, pts);

      /// Add successors of current stmt if its pts has been changed.
      updateCachedPointsTo(dpm, pts);
    }
    return getCachedPointsTo(dpm);
  }

protected:
  // [OS-CFI] matchCallInstArgmunet(): return true if call instruction has the
  // matched argument
  bool matchCallInstArgmunet(llvm::Instruction *call, const llvm::Value *arg,
                             unsigned int argNo) {
    llvm::CallInst *callInst = nullptr;
    llvm::InvokeInst *invokeInst = nullptr;
    if (llvm::isa<llvm::CallInst>(call)) {
      callInst = llvm::dyn_cast<llvm::CallInst>(call);
      if (callInst->getNumArgOperands() > argNo &&
          callInst->getArgOperand(argNo) == arg) {
        return true;
      }
    } else if (llvm::isa<llvm::InvokeInst>(call)) {
      invokeInst = llvm::dyn_cast<llvm::InvokeInst>(call);
      if (invokeInst->getNumArgOperands() > argNo &&
          invokeInst->getArgOperand(argNo) == arg) {
        return true;
      }
    }
    return false;
  }

  // [OS-CFI] getInstructionForTargetFunction(): return instruction if source
  // statement target to a function
  llvm::Instruction *
  getInstructionForTargetFunction(const llvm::Instruction *srcStmt,
                                  const llvm::Function *target,
                                  const llvm::Value *addr, unsigned int argNo) {
    llvm::CallInst *callInst = nullptr;
    llvm::InvokeInst *invokeInst = nullptr;
    llvm::Instruction *inst = (llvm::Instruction *)srcStmt;
    if (llvm::isa<llvm::CallInst>(inst)) {
      callInst = llvm::dyn_cast<llvm::CallInst>(inst);
      if ((callInst->getCalledFunction() == target ||
           callInst->getCalledFunction() == NULL) &&
          matchCallInstArgmunet(callInst, addr, argNo)) {
        return callInst;
      }
    } else if (llvm::isa<llvm::InvokeInst>(inst)) {
      invokeInst = llvm::dyn_cast<llvm::InvokeInst>(inst);
      if ((invokeInst->getCalledFunction() == target ||
           invokeInst->getCalledFunction() == NULL) &&
          matchCallInstArgmunet(invokeInst, addr, argNo)) {
        return invokeInst;
      }
    }
    return nullptr;
  }

  // [OS-CFI] getMatchedCallInstruction(): return instruction if search found
  // the expected call instruction
  llvm::Instruction *getMatchedCallInstruction(const llvm::Instruction *srcStmt,
                                               const llvm::Function *target,
                                               unsigned int argNo) {
    llvm::CallInst *callInst = nullptr;
    llvm::InvokeInst *invokeInst = nullptr;
    llvm::Instruction *inst = (llvm::Instruction *)srcStmt;
    while (1) {
      if (llvm::isa<llvm::CallInst>(inst)) {
        callInst = llvm::dyn_cast<llvm::CallInst>(inst);
        if ((callInst->getCalledFunction() == target ||
             callInst->getCalledFunction() == NULL) &&
            matchCallInstArgmunet(callInst, srcStmt, argNo)) {
          return callInst;
        }
      } else if (llvm::isa<llvm::InvokeInst>(inst)) {
        invokeInst = llvm::dyn_cast<llvm::InvokeInst>(inst);
        if ((invokeInst->getCalledFunction() == target ||
             invokeInst->getCalledFunction() == NULL) &&
            matchCallInstArgmunet(invokeInst, srcStmt, argNo)) {
          return invokeInst;
        }
      }
      if (inst->isTerminator()) {
        return nullptr;
      }
      inst = inst->getNextNonDebugInstruction();
    }
    return nullptr;
  }

  // [OS-CFI] isInstStoreFnptr(): return true if the store instruction stores to
  // a function pointer
  bool isInstStoreFnptr(const llvm::Instruction *initInst) {
    llvm::Instruction *inst = (llvm::Instruction *)initInst;
    llvm::Instruction *ninst =
        (llvm::Instruction *)inst->getNextNonDebugInstruction();
    if (llvm::isa<llvm::CallInst>(ninst)) {
      llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(ninst);
      if (call->getCalledFunction() &&
          call->getCalledFunction()->getName() == "llvm.returnaddress")
        return true;
    }

    llvm::Instruction *binst = inst->getParent()->getFirstNonPHI();
    llvm::StoreInst *sinst = llvm::dyn_cast<llvm::StoreInst>(inst);

    while (1) {
      if (binst->getNextNonDebugInstruction() == inst &&
          llvm::isa<llvm::CallInst>(binst)) {
        llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(binst);
        if (call->getNumArgOperands() >= 3 &&
            call->getArgOperand(0) == sinst->getValueOperand()) {
          return true;
        }
      }
      if (binst->isTerminator()) {
        break;
      }
      binst = binst->getNextNonDebugInstruction();
    }
    return false;
  }

  // [OS-CFI] handleOSenEdge(): test SVFGEdges direct or indiret,
  // it will check if any edge is part of callsite context if so, it will either
  // add the new callsite or keep it mapping with previous nodes it also keep
  // the consistent mapping for recent store instruction
  void handleOSenEdge(const DPIm &oldDpm, const SVFGEdge *edge) {
    const SVFGNode *srcNode = edge->getSrcNode();
    const SVFGNode *dstNode = edge->getDstNode();
    const StmtSVFGNode *srcStmt = nullptr;
    const StmtSVFGNode *dstStmt = nullptr;
    const llvm::Function *srcFunc = nullptr;
    const llvm::Function *dstFunc = nullptr;

    if (srcNode && llvm::isa<StmtSVFGNode>(srcNode)) {
      srcStmt = llvm::dyn_cast<StmtSVFGNode>(srcNode);
      if (srcStmt && srcStmt->getInst())
        srcFunc = srcStmt->getInst()->getParent()->getParent();
    }
    if (dstNode && llvm::isa<StmtSVFGNode>(dstNode)) {
      dstStmt = llvm::dyn_cast<StmtSVFGNode>(dstNode);
      if (dstStmt && dstStmt->getInst())
        dstFunc = dstStmt->getInst()->getParent()->getParent();
    }

    if (DEBUG_DETAILS && srcStmt && srcStmt->getInst() && dstStmt &&
        dstStmt->getInst()) {
      llvm::outs() << "[OS-CFI] Source Statement{" << srcNode->getId()
                   << "}: " << *srcStmt->getInst() << "["
                   << srcFunc->getName().str() << "]\n";
      llvm::outs() << "[OS-CFI] Destination Statement{" << dstNode->getId()
                   << "}: " << *dstStmt->getInst() << "["
                   << dstFunc->getName().str() << "]\n";
    }

    if (llvm::isa<IndirectSVFGEdge>(edge) &&
        ((setCallStack.size() > 0 && setCallStack.top().second != nullptr) ||
         setCallStack.size() == 0)) {
      if (srcFunc != dstFunc) {
        setCallStack.push(std::make_pair(oldDpm.getLoc()->getId(), nullptr));
      } else if (!dstStmt) {
        setCallStack.push(std::make_pair(oldDpm.getLoc()->getId(), nullptr));
      }
      dumpCallStack();
    }

    if (mapNodeStore.count(edge->getDstID()) > 0) {
      mapNodeStore[edge->getSrcID()] = mapNodeStore[edge->getDstID()];
      if (DEBUG_SOLVER)
        llvm::outs() << "[OS-CFI] mapNodeStore[" << edge->getSrcID()
                     << "] = mapNodeStore[" << edge->getDstID() << "]";
    }

    InstructionSet orgCtxSet;

    if (const InterPHISVFGNode *interphiparam =
            llvm::dyn_cast<InterPHISVFGNode>(dstNode)) {
      if (interphiparam->isFormalParmPHI()) {
        unsigned int argNo = -1;
        if (llvm::isa<llvm::Argument>(interphiparam->getRes()->getValue())) {
          const llvm::Argument *arg = llvm::dyn_cast<llvm::Argument>(
              interphiparam->getRes()->getValue());
          argNo = arg->getArgNo();
        }

        const llvm::Instruction *srcStmt = nullptr;
        const llvm::Value *argAddr = nullptr;
        PAGNode *copyPag = nullptr;

        if (const AddrSVFGNode *addr = llvm::dyn_cast<AddrSVFGNode>(srcNode)) {
          copyPag = (_pag->getPAGNode(oldDpm.getCurNodeID()));
          argAddr = (_pag->getPAGNode(addr->getPAGSrcNodeID()))->getValue();
        } else if (const StmtSVFGNode *stmt =
                       llvm::dyn_cast<StmtSVFGNode>(srcNode)) {
          srcStmt = stmt->getInst();
        }

        if (srcStmt) {
          llvm::Instruction *call = getMatchedCallInstruction(
              srcStmt, interphiparam->getFun(), argNo);
          if (call) {
            orgCtxSet.insert(call);
            CallSwitchPair tmp = std::make_pair(oldDpm.getLoc()->getId(), call);
            if (setCallStack.size() == 0 ||
                (setCallStack.size() > 0 && setCallStack.top() != tmp)) {
              setCallStack.push(tmp);
              dumpCallStack();
            }
          }
        } else if (copyPag) {
          if (copyPag->hasIncomingEdges(PAGEdge::PEDGEK::Call)) {
            for (PAGEdge::PAGEdgeSetTy::iterator
                     inIt =
                         copyPag->getIncomingEdgesBegin(PAGEdge::PEDGEK::Call),
                     inEit =
                         copyPag->getIncomingEdgesEnd(PAGEdge::PEDGEK::Call);
                 inIt != inEit; ++inIt) {
              PAGEdge *edge = *inIt;
              llvm::Instruction *call = getInstructionForTargetFunction(
                  edge->getInst(), interphiparam->getFun(), argAddr, argNo);
              if (call) {
                orgCtxSet.insert(call);

                CallSwitchPair tmp =
                    std::make_pair(oldDpm.getLoc()->getId(), call);
                if (setCallStack.size() == 0 ||
                    (setCallStack.size() > 0 && setCallStack.top() != tmp)) {
                  setCallStack.push(tmp);
                  dumpCallStack();
                }
              }
            }
          }
        }
      }
    }

    if (mapTOrgCtx.count(edge->getDstID()) > 0) {
      mapTOrgCtx[edge->getSrcID()] = mapTOrgCtx[edge->getDstID()];
      if (DEBUG_SOLVER) {
        llvm::outs() << "[OS-CFI] mapTOrgCtx[" << edge->getSrcID()
                     << "] = mapTOrgCtx[" << edge->getDstID() << "]\n";
      }
    } else {
      if (!orgCtxSet.empty()) {
        for (InstructionSetIt orgCtxSetIt = orgCtxSet.begin();
             orgCtxSetIt != orgCtxSet.end(); orgCtxSetIt++) {
          mapTOrgCtx[edge->getSrcID()].insert(*orgCtxSetIt);
          if (DEBUG_SOLVER)
            llvm::outs() << "[OS-CFI] mapTOrgCtx[" << edge->getSrcID()
                         << "] = " << **orgCtxSetIt << "\n";
        }
      }
    }
  }

  /// Handle single statement
  virtual void handleSingleStatement(const DPIm &dpm, CPtSet &pts) {
    /// resolve function pointer first at indirect callsite
    resolveFunPtr(dpm);

    const SVFGNode *node = dpm.getLoc();
    if (llvm::isa<AddrSVFGNode>(node)) {
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] AddrSVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      handleAddr(pts, dpm, llvm::cast<AddrSVFGNode>(node));
    } else if (llvm::isa<CopySVFGNode>(node) || llvm::isa<PHISVFGNode>(node) ||
               llvm::isa<ActualParmSVFGNode>(node) ||
               llvm::isa<FormalParmSVFGNode>(node) ||
               llvm::isa<ActualRetSVFGNode>(node) ||
               llvm::isa<FormalRetSVFGNode>(node) ||
               llvm::isa<NullPtrSVFGNode>(node)) {
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] CopySVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      backtraceAlongDirectVF(pts, dpm);
    } else if (llvm::isa<GepSVFGNode>(node)) {
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] GEPSVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      CPtSet gepPts;
      backtraceAlongDirectVF(gepPts, dpm);
      unionDDAPts(pts, processGepPts(llvm::cast<GepSVFGNode>(node), gepPts));
    } else if (llvm::isa<LoadSVFGNode>(node)) {
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] LoadSVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      CPtSet loadpts;
      startNewPTCompFromLoadSrc(loadpts, dpm);
      for (typename CPtSet::iterator it = loadpts.begin(), eit = loadpts.end();
           it != eit; ++it) {
        backtraceAlongIndirectVF(pts, getDPImWithOldCond(dpm, *it, node));
      }
    } else if (llvm::isa<StoreSVFGNode>(node)) {
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] StoreSVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      if (isMustAlias(getLoadDpm(dpm), dpm)) {
        DBOUT(DDDA, llvm::outs() << "+++must alias for load and store:");
        DBOUT(DDDA, getLoadDpm(dpm).dump());
        DBOUT(DDDA, dpm.dump());
        DBOUT(DDDA, llvm::outs() << "+++\n");
        DOSTAT(ddaStat->_NumOfMustAliases++);
        backtraceToStoreSrc(pts, dpm);
      } else {
        CPtSet storepts;
        startNewPTCompFromStoreDst(storepts, dpm);
        for (typename CPtSet::iterator it = storepts.begin(),
                                       eit = storepts.end();
             it != eit; ++it) {
          if (propagateViaObj(*it, getLoadCVar(dpm))) {
            backtraceToStoreSrc(pts, getDPImWithOldCond(dpm, *it, node));

            if (isStrongUpdate(storepts, llvm::cast<StoreSVFGNode>(node))) {
              DBOUT(DDDA, llvm::outs() << "backward strong update for obj "
                                       << dpm.getCurNodeID() << "\n");
              DOSTAT(addSUStat(dpm, node);)
            } else {
              DOSTAT(rmSUStat(dpm, node);)
              backtraceAlongIndirectVF(pts, getDPImWithOldCond(dpm, *it, node));
            }
          } else {
            backtraceAlongIndirectVF(pts, dpm);
          }
        }
      }
    } else if (llvm::isa<MRSVFGNode>(node)) {
      // [OS-CFI] ToDo
      NodeID curNode = _pag->getPAGNode(dpm.getCurNodeID())->getId();
      if (DEBUG_DETAILS) {
        llvm::outs() << "[OS-CFI] [" << getCurCandidate() << "] MRSVFGNode: "
                     << *(_pag->getPAGNode(dpm.getCurNodeID())) << "\n";
      }
      NodeID obj = dpm.getCurNodeID();
      if (!(_pag->isConstantObj(obj) || _pag->isNonPointerObj(obj))) {
        const SVFGEdgeSet edgeSet(node->getInEdges());
        for (SVFGNode::const_iterator it = edgeSet.begin(), eit = edgeSet.end();
             it != eit; ++it) {
          if (const IndirectSVFGEdge *indirEdge =
                  llvm::dyn_cast<IndirectSVFGEdge>(*it)) {
            PointsTo &guard = const_cast<PointsTo &>(indirEdge->getPointsTo());
            if (guard.test(obj)) {
              const SVFGNode *srcNode = indirEdge->getSrcNode();
              if (mapNodeStore.count(curNode) > 0) {
                mapNodeStore[srcNode->getId()] = mapNodeStore[curNode];
                if (DEBUG_SOLVER) {
                  llvm::outs() << "[OS-CFI] mapNodeStore[" << srcNode->getId()
                               << "] = mapNodeStore[" << curNode << "]\n";
                }
                if (mapTOrgCtx.count(curNode) > 0) {
                  mapTOrgCtx[srcNode->getId()] = mapTOrgCtx[curNode];
                  if (DEBUG_SOLVER) {
                    llvm::outs() << "[OS-CFI] mapTOrgCtx[" << srcNode->getId()
                                 << "] = mapTOrgCtx[" << curNode << "]\n";
                  }
                }
              }
            }
          }
        }
      }
      backtraceAlongIndirectVF(pts, dpm);
    } else
      assert(false && "unexpected kind of SVFG nodes");
  }

  /// recompute points-to for value-flow cycles and indirect calls
  void reCompute(const DPIm &dpm) {
    /// re-compute due to indirect calls
    SVFGEdgeSet newIndirectEdges;
    if (_pag->isFunPtr(dpm.getCurNodeID())) {
      const CallSiteSet &csSet = _pag->getIndCallSites(dpm.getCurNodeID());
      for (CallSiteSet::const_iterator it = csSet.begin(), eit = csSet.end();
           it != eit; ++it)
        updateCallGraphAndSVFG(dpm, *it, newIndirectEdges);
    }
    /// callgraph scc detection for local variable in recursion
    if (!newIndirectEdges.empty())
      _callGraphSCC->find();
    reComputeForEdges(dpm, newIndirectEdges, true);

    /// re-compute for transitive closures
    SVFGEdgeSet edgeSet(dpm.getLoc()->getOutEdges());
    reComputeForEdges(dpm, edgeSet, false);
  }

  /// Traverse along out edges to find all nodes which may be affected by
  /// locDPM.
  void reComputeForEdges(const DPIm &dpm, const SVFGEdgeSet &edgeSet,
                         bool indirectCall = false) {
    for (SVFGNode::const_iterator it = edgeSet.begin(), eit = edgeSet.end();
         it != eit; ++it) {
      const SVFGEdge *edge = *it;
      const SVFGNode *dst = edge->getDstNode();
      typename LocToDPMVecMap::const_iterator locIt =
          getLocToDPMVecMap().find(dst->getId());
      /// Only collect nodes we have traversed
      if (locIt == getLocToDPMVecMap().end())
        continue;
      DPTItemSet dpmSet(locIt->second.begin(), locIt->second.end());
      for (typename DPTItemSet::const_iterator it = dpmSet.begin(),
                                               eit = dpmSet.end();
           it != eit; ++it) {
        const DPIm &dstDpm = *it;
        if (!indirectCall && llvm::isa<IndirectSVFGEdge>(edge) &&
            !llvm::isa<LoadSVFGNode>(edge->getDstNode())) {
          if (dstDpm.getCurNodeID() == dpm.getCurNodeID()) {
            DBOUT(DDDA, llvm::outs() << "\t Recompute, forward from :");
            DBOUT(DDDA, dpm.dump());
            DOSTAT(ddaStat->_NumOfStepInCycle++);
            clearbkVisited(dstDpm);
            findPT(dstDpm);
          }
        } else {
          if (indirectCall)
            DBOUT(DDDA, llvm::outs()
                            << "\t Recompute for indirect call from :");
          else
            DBOUT(DDDA, llvm::outs() << "\t Recompute forward from :");
          DBOUT(DDDA, dpm.dump());
          DOSTAT(ddaStat->_NumOfStepInCycle++);
          clearbkVisited(dstDpm);
          findPT(dstDpm);
        }
      }
    }
  }

  /// Build SVFG
  virtual inline void buildSVFG(SVFModule module) {
    _ander = AndersenWaveDiff::createAndersenWaveDiff(module);
    _svfg = svfgBuilder.buildSVFG(_ander, true);
    _pag = _svfg->getPAG();
  }
  /// Reset visited map for next points-to query
  virtual inline void resetQuery() {
    if (outOfBudgetQuery)
      OOBResetVisited();

    locToDpmSetMap.clear();
    dpmToloadDpmMap.clear();
    loadToPTCVarMap.clear();
    outOfBudgetQuery = false;
    ddaStat->_NumOfStep = 0;

    // [OS-CFI] reset data before every query
    mapNodeStore.clear();
    mapTOrgCtx.clear();
    // storeToDPMs.clear();
    // dpmToTLCPtSetMap.clear();
    // dpmToADCPtSetMap.clear();
    // backwardVisited.clear();
    clearCallStack();
  }
  /// Reset visited map if the current query is out-of-budget
  inline void OOBResetVisited() {
    for (typename LocToDPMVecMap::const_iterator it = locToDpmSetMap.begin(),
                                                 eit = locToDpmSetMap.end();
         it != eit; ++it) {
      DPTItemSet dpmSet(it->second.begin(), it->second.end());
      for (typename DPTItemSet::const_iterator dit = dpmSet.begin(),
                                               deit = dpmSet.end();
           dit != deit; ++dit)
        if (isOutOfBudgetDpm(*dit) == false)
          clearbkVisited(*dit);
    }
  }

  /// GetDefinition SVFG
  inline const SVFGNode *getDefSVFGNode(const PAGNode *pagNode) const {
    return getSVFG()->getDefSVFGNode(pagNode);
  }

  /// Backward traverse along indirect value flows
  void backtraceAlongIndirectVF(CPtSet &pts, const DPIm &oldDpm) {
    const SVFGNode *node = oldDpm.getLoc();
    NodeID obj = oldDpm.getCurNodeID();
    if (_pag->isConstantObj(obj) || _pag->isNonPointerObj(obj))
      return;
    const SVFGEdgeSet edgeSet(node->getInEdges());
    for (SVFGNode::const_iterator it = edgeSet.begin(), eit = edgeSet.end();
         it != eit; ++it) {
      if (const IndirectSVFGEdge *indirEdge =
              llvm::dyn_cast<IndirectSVFGEdge>(*it)) {
        PointsTo &guard = const_cast<PointsTo &>(indirEdge->getPointsTo());
        if (guard.test(obj)) {
          DBOUT(DDDA, llvm::outs() << "\t\t==backtrace indirectVF svfgNode "
                                   << indirEdge->getDstID() << " --> "
                                   << indirEdge->getSrcID() << "\n");

          // [OS-CFI] ToDo
          const SVFGNode *srcNode = indirEdge->getSrcNode();
          handleOSenEdge(oldDpm, indirEdge);

          backwardPropDpm(pts, oldDpm.getCurNodeID(), oldDpm, indirEdge);

          if (setCallStack.size() > 0 &&
              setCallStack.top().first == oldDpm.getLoc()->getId()) {
            CallSwitchPair tmp = setCallStack.top();
            setCallStack.pop();
            dumpCallStack();
          }
        }
      }
    }
  }

  /// Backward traverse along direct value flows
  void backtraceAlongDirectVF(CPtSet &pts, const DPIm &oldDpm) {
    const SVFGNode *node = oldDpm.getLoc();
    const SVFGEdgeSet edgeSet(node->getInEdges());
    for (SVFGNode::const_iterator it = edgeSet.begin(), eit = edgeSet.end();
         it != eit; ++it) {
      if (const DirectSVFGEdge *dirEdge = llvm::dyn_cast<DirectSVFGEdge>(*it)) {
        DBOUT(DDDA, llvm::outs() << "\t\t==backtrace directVF svfgNode "
                                 << dirEdge->getDstID() << " --> "
                                 << dirEdge->getSrcID() << "\n");
        const SVFGNode *srcNode = dirEdge->getSrcNode();
        // [OS-CFI] ToDo
        handleOSenEdge(oldDpm, dirEdge);

        backwardPropDpm(pts, getSVFG()->getLHSTopLevPtr(srcNode)->getId(),
                        oldDpm, dirEdge);
        if (setCallStack.size() > 0 &&
            setCallStack.top().first == oldDpm.getLoc()->getId()) {
          CallSwitchPair tmp = setCallStack.top();
          setCallStack.pop();
          dumpCallStack();
        }
      }
    }
  }

  /// Backward traverse for top-level pointers of load/store statements
  ///@{
  inline void startNewPTCompFromLoadSrc(CPtSet &pts, const DPIm &oldDpm) {
    const LoadSVFGNode *load = llvm::cast<LoadSVFGNode>(oldDpm.getLoc());
    const SVFGNode *loadSrc = getDefSVFGNode(load->getPAGSrcNode());
    DBOUT(DDDA, llvm::outs()
                    << "!##start new computation from loadSrc svfgNode "
                    << load->getId() << " --> " << loadSrc->getId() << "\n");

    // [OS-CFI] ToDo
    if (load && load->getInst()) {
      if (mapNodeStore.count(loadSrc->getId()) > 0) {
        mapNodeStore[load->getId()] = mapNodeStore[loadSrc->getId()];
        if (DEBUG_SOLVER)
          llvm::outs() << "[OS-CFI] mapNodeStore[" << load->getId()
                       << "] = mapNodeStore[" << loadSrc->getId() << "]\n";
      }
    }

    if (mapTOrgCtx.count(loadSrc->getId()) > 0) {
      mapTOrgCtx[load->getId()] = mapTOrgCtx[loadSrc->getId()];
      if (DEBUG_SOLVER)
        llvm::outs() << "[oCFG] mapTOrgCtx[" << load->getId()
                     << "] = mapTOrgCtx[" << loadSrc->getId() << "]\n";
    }

    const SVFGEdge *edge =
        getSVFG()->getSVFGEdge(loadSrc, load, SVFGEdge::IntraDirect);
    assert(edge && "Edge not found!!");
    backwardPropDpm(pts, load->getPAGSrcNodeID(), oldDpm, edge);
  }

  inline void startNewPTCompFromStoreDst(CPtSet &pts, const DPIm &oldDpm) {
    const StoreSVFGNode *store = llvm::cast<StoreSVFGNode>(oldDpm.getLoc());
    const SVFGNode *storeDst = getDefSVFGNode(store->getPAGDstNode());
    DBOUT(DDDA, llvm::outs()
                    << "!##start new computation from storeDst svfgNode "
                    << store->getId() << " --> " << storeDst->getId() << "\n");

    // [OS-CFI] ToDo
    if (mapNodeStore.count(storeDst->getId()) > 0) {
      mapNodeStore[store->getId()] = mapNodeStore[storeDst->getId()];
      if (DEBUG_SOLVER)
        llvm::outs() << "[OS-CFI] mapNodeStore[" << store->getId()
                     << "] = mapNodeStore[" << storeDst->getId() << "]\n";
    }

    if (mapTOrgCtx.count(storeDst->getId()) > 0) {
      mapTOrgCtx[store->getId()] = mapTOrgCtx[storeDst->getId()];
      if (DEBUG_SOLVER)
        llvm::outs() << "[oCFG] <OriginContext> mapTOrgCtx[" << store->getId()
                     << "] = mapTOrgCtx[" << storeDst->getId() << "]\n";
    }

    const SVFGEdge *edge =
        getSVFG()->getSVFGEdge(storeDst, store, SVFGEdge::IntraDirect);
    assert(edge && "Edge not found!!");
    backwardPropDpm(pts, store->getPAGDstNodeID(), oldDpm, edge);
  }

  inline void backtraceToStoreSrc(CPtSet &pts, const DPIm &oldDpm) {
    const StoreSVFGNode *store = llvm::cast<StoreSVFGNode>(oldDpm.getLoc());
    const SVFGNode *storeSrc = getDefSVFGNode(store->getPAGSrcNode());
    DBOUT(DDDA, llvm::outs()
                    << "++backtrace to storeSrc from svfgNode "
                    << getLoadDpm(oldDpm).getLoc()->getId() << " to "
                    << store->getId() << " to " << storeSrc->getId() << "\n");

    // [OS-CFI] ToDo
    if (store && store->getInst()) {
      if (mapNodeStore.count(store->getId()) > 0) {
        mapNodeStore[storeSrc->getId()] = mapNodeStore[store->getId()];
        if (DEBUG_SOLVER)
          llvm::outs() << "[oCFG] mapNodeStore[" << storeSrc->getId()
                       << "] = mapNodeStore[" << store->getId() << "]\n";
      } else if (store && store->getInst() &&
                 llvm::isa<llvm::Instruction>(store->getInst())) {
        const llvm::Instruction *inst =
            llvm::dyn_cast<llvm::Instruction>(store->getInst());
        if (isInstStoreFnptr(inst)) {
          mapNodeStore[storeSrc->getId()] = store;
          if (DEBUG_SOLVER) {
            llvm::outs() << "[oCFG] mapNodeStore[" << storeSrc->getId()
                         << "] = " << *store << "\n";
          }
        }
      }
    }

    if (mapTOrgCtx.count(store->getId()) > 0) {
      mapTOrgCtx[storeSrc->getId()] = mapTOrgCtx[store->getId()];
      if (DEBUG_SOLVER)
        llvm::outs() << "[oCFG] mapTOrgCtx[" << storeSrc->getId()
                     << "] = mapTOrgCtx[" << store->getId() << "]\n";
    }

    const SVFGEdge *edge =
        getSVFG()->getSVFGEdge(storeSrc, store, SVFGEdge::IntraDirect);
    assert(edge && "Edge not found!!");
    backwardPropDpm(pts, store->getPAGSrcNodeID(), oldDpm, edge);
  }
  //@}

  /// dpm transit during backward tracing
  virtual void backwardPropDpm(CPtSet &pts, NodeID ptr, const DPIm &oldDpm,
                               const SVFGEdge *edge) {
    DPIm dpm(oldDpm);
    dpm.setLocVar(edge->getSrcNode(), ptr);
    DOTIMESTAT(double start = DDAStat::getClk());
    /// handle context-/path- sensitivity
    if (handleBKCondition(dpm, edge) == false) {
      DOTIMESTAT(ddaStat->_TotalTimeOfBKCondition += DDAStat::getClk() - start);
      DBOUT(DDDA, llvm::outs()
                      << "\t!!! infeasible path svfgNode: " << edge->getDstID()
                      << " --| " << edge->getSrcID() << "\n");
      DOSTAT(ddaStat->_NumOfInfeasiblePath++);
      return;
    }

    /// record the source of load dpm
    if (llvm::isa<IndirectSVFGEdge>(edge))
      addLoadDpmAndCVar(dpm, getLoadDpm(oldDpm), getLoadCVar(oldDpm));

    DOSTAT(ddaStat->_NumOfDPM++);
    /// handle out of budget case
    unionDDAPts(pts, findPT(dpm));
  }
  /// whether load and store are aliased
  virtual bool isMustAlias(const DPIm &loadDpm, const DPIm &storeDPm) {
    return false;
  }
  /// Return TRUE if this is a strong update STORE statement.
  virtual bool isStrongUpdate(const CPtSet &dstCPSet,
                              const StoreSVFGNode *store) {
    if (dstCPSet.count() == 1) {
      /// Find the unique element in cpts
      typename CPtSet::iterator it = dstCPSet.begin();
      const CVar &var = *it;
      // Strong update can be made if this points-to target is not heap, array
      // or field-insensitive.
      if (!isHeapCondMemObj(var, store) && !isArrayCondMemObj(var) &&
          !isFieldInsenCondMemObj(var) && !isLocalCVarInRecursion(var)) {
        return true;
      }
    }
    return false;
  }
  /// Whether a local variable is in function recursions
  virtual inline bool isLocalCVarInRecursion(const CVar &var) const {
    NodeID id = getPtrNodeID(var);
    const MemObj *obj = _pag->getObject(id);
    assert(obj && "object not found!!");
    if (obj->isStack()) {
      if (const llvm::AllocaInst *local =
              llvm::dyn_cast<llvm::AllocaInst>(obj->getRefVal())) {
        const llvm::Function *fun = local->getParent()->getParent();
        return _callGraphSCC->isInCycle(
            _callGraph->getCallGraphNode(fun)->getId());
      }
    }
    return false;
  }

  /// If the points-to contain the object obj, we could move forward along
  /// indirect value-flow edge
  virtual inline bool propagateViaObj(const CVar &storeObj,
                                      const CVar &loadObj) {
    if (getPtrNodeID(storeObj) == getPtrNodeID(loadObj))
      return true;
    return false;
  }
  /// resolve function pointer
  void resolveFunPtr(const DPIm &dpm) {
    if (llvm::Instruction *callInst =
            getSVFG()->isCallSiteRetSVFGNode(dpm.getLoc())) {
      llvm::CallSite cs = analysisUtil::getLLVMCallSite(callInst);
      if (_pag->isIndirectCallSites(cs)) {
        NodeID funPtr = _pag->getFunPtr(cs);
        DPIm funPtrDpm(dpm);
        funPtrDpm.setLocVar(getSVFG()->getDefSVFGNode(_pag->getPAGNode(funPtr)),
                            funPtr);
        findPT(funPtrDpm);
      }
    } else if (const llvm::Function *fun =
                   getSVFG()->isFunEntrySVFGNode(dpm.getLoc())) {
      CallInstSet csSet;
      /// use pre-analysis call graph to approximate all potential callsites
      _ander->getPTACallGraph()->getIndCallSitesInvokingCallee(fun, csSet);
      for (CallInstSet::const_iterator it = csSet.begin(), eit = csSet.end();
           it != eit; ++it) {
        llvm::CallSite cs = analysisUtil::getLLVMCallSite(*it);
        NodeID funPtr = _pag->getFunPtr(cs);
        DPIm funPtrDpm(dpm);
        funPtrDpm.setLocVar(getSVFG()->getDefSVFGNode(_pag->getPAGNode(funPtr)),
                            funPtr);
        findPT(funPtrDpm);
      }
    }
  }
  /// Methods to be implemented in child class
  //@{
  /// Get variable ID (PAGNodeID) according to CVar
  virtual NodeID getPtrNodeID(const CVar &var) const = 0;
  /// ProcessGep node to generate field object nodes of a struct
  virtual CPtSet processGepPts(const GepSVFGNode *gep,
                               const CPtSet &srcPts) = 0;
  /// Handle AddrSVFGNode to add proper points-to
  virtual void handleAddr(CPtSet &pts, const DPIm &dpm,
                          const AddrSVFGNode *addr) = 0;
  /// Get conservative points-to results when the query is out of budget
  virtual CPtSet getConservativeCPts(const DPIm &dpm) = 0;
  /// Handle condition for context or path analysis (backward analysis)
  virtual inline bool handleBKCondition(DPIm &oldDpm, const SVFGEdge *edge) {
    return true;
  }
  /// Update call graph
  virtual inline void updateCallGraphAndSVFG(const DPIm &dpm, llvm::CallSite cs,
                                             SVFGEdgeSet &svfgEdges) {}
  //@}

  /// Visited flags to avoid cycles
  //@{
  inline void markbkVisited(const DPIm &dpm) { backwardVisited.insert(dpm); }
  inline bool isbkVisited(const DPIm &dpm) {
    return backwardVisited.find(dpm) != backwardVisited.end();
  }
  inline void clearbkVisited(const DPIm &dpm) {
    assert(backwardVisited.find(dpm) != backwardVisited.end() &&
           "dpm not found!");
    backwardVisited.erase(dpm);
  }
  //@}

  /// Points-to Caching for top-level pointers and address-taken objects
  //@{
  virtual inline CPtSet &getCachedPointsTo(const DPIm &dpm) {
    if (isTopLevelPtrStmt(dpm.getLoc()))
      return getCachedTLPointsTo(dpm);
    else
      return getCachedADPointsTo(dpm);
  }
  virtual inline void updateCachedPointsTo(const DPIm &dpm, CPtSet &pts) {
    CPtSet &dpmPts = getCachedPointsTo(dpm);
    if (unionDDAPts(dpmPts, pts)) {
      DOSTAT(double start = DDAStat::getClk());
      reCompute(dpm);
      DOSTAT(ddaStat->_AnaTimeCyclePerQuery += DDAStat::getClk() - start);
    }
  }
  virtual inline CPtSet &getCachedTLPointsTo(const DPIm &dpm) {
    return dpmToTLCPtSetMap[dpm];
  }
  virtual inline CPtSet &getCachedADPointsTo(const DPIm &dpm) {
    return dpmToADCPtSetMap[dpm];
  }
  //@}

  /// Whether this is a top-level pointer statement
  inline bool isTopLevelPtrStmt(const SVFGNode *stmt) {
    if (llvm::isa<StoreSVFGNode>(stmt) || llvm::isa<MRSVFGNode>(stmt))
      return false;
    else
      return true;
  }
  /// Return dpm with old context and path conditions
  virtual inline DPIm getDPImWithOldCond(const DPIm &oldDpm, const CVar &var,
                                         const SVFGNode *loc) {
    DPIm dpm(oldDpm);
    dpm.setLocVar(loc, getPtrNodeID(var));

    if (llvm::isa<StoreSVFGNode>(loc))
      addLoadDpmAndCVar(dpm, getLoadDpm(oldDpm), var);

    if (llvm::isa<LoadSVFGNode>(loc))
      addLoadDpmAndCVar(dpm, oldDpm, var);

    DOSTAT(ddaStat->_NumOfDPM++);
    return dpm;
  }
  /// SVFG SCC detection
  inline void SVFGSCCDetection() {
    if (_svfgSCC == NULL) {
      _svfgSCC = new SVFGSCC(getSVFG());
    }
    _svfgSCC->find();
  }
  /// Get SCC rep node of a SVFG node.
  inline NodeID getSVFGSCCRepNode(NodeID id) { return _svfgSCC->repNode(id); }
  /// Return whether this SVFGNode is in cycle
  inline bool isSVFGNodeInCycle(const SVFGNode *node) {
    return _svfgSCC->isInCycle(node->getId());
  }
  /// Return TRUE if this edge is inside a SVFG SCC, i.e., src node and dst
  /// node are in the same SCC on the SVFG.
  inline bool edgeInSVFGSCC(const SVFGEdge *edge) {
    return (getSVFGSCCRepNode(edge->getSrcID()) ==
            getSVFGSCCRepNode(edge->getDstID()));
  }
  /// Set callgraph
  inline void setCallGraph(PTACallGraph *cg) { _callGraph = cg; }
  /// Set callgraphSCC
  inline void setCallGraphSCC(CallGraphSCC *scc) { _callGraphSCC = scc; }
  /// Check heap and array object
  //@{
  virtual inline bool isHeapCondMemObj(const CVar &var,
                                       const StoreSVFGNode *store) {
    const MemObj *mem = _pag->getObject(getPtrNodeID(var));
    assert(mem && "memory object is null??");
    return mem->isHeap();
  }

  inline bool isArrayCondMemObj(const CVar &var) const {
    const MemObj *mem = _pag->getObject(getPtrNodeID(var));
    assert(mem && "memory object is null??");
    return mem->isArray();
  }
  inline bool isFieldInsenCondMemObj(const CVar &var) const {
    const MemObj *mem = _pag->getBaseObj(getPtrNodeID(var));
    return mem->isFieldInsensitive();
  }
  //@}
private:
  /// Map a SVFGNode to its dpms for handling value-flow cycles
  //@{
  inline const LocToDPMVecMap &getLocToDPMVecMap() const {
    return locToDpmSetMap;
  }
  inline const DPTItemSet &getDpmSetAtLoc(const SVFGNode *loc) {
    return locToDpmSetMap[loc->getId()];
  }
  inline void addDpmToLoc(const DPIm &dpm) {
    locToDpmSetMap[dpm.getLoc()->getId()].insert(dpm);
  }
  inline void removeDpmFromLoc(const DPIm &dpm) {
    assert(dpm == locToDpmSetMap[dpm.getLoc()].back() &&
           "dpm not match with the end of vector");
    locToDpmSetMap[dpm.getLoc()->getId()].erase(dpm);
  }
  //@}
protected:
  /// LoadDpm for must-alias analysis
  //@{
  inline void addLoadDpmAndCVar(const DPIm &dpm, const DPIm &loadDpm,
                                const CVar &loadVar) {
    addLoadCVar(dpm, loadVar);
    addLoadDpm(dpm, loadDpm);
  }
  /// Note that simply use "dpmToloadDpmMap[dpm]=loadDpm", requires DPIm have
  /// a default constructor
  inline void addLoadDpm(const DPIm &dpm, const DPIm &loadDpm) {
    typename DPMToDPMMap::iterator it = dpmToloadDpmMap.find(dpm);
    if (it != dpmToloadDpmMap.end())
      it->second = loadDpm;
    else
      dpmToloadDpmMap.insert(std::make_pair(dpm, loadDpm));
  }
  inline const DPIm &getLoadDpm(const DPIm &dpm) const {
    typename DPMToDPMMap::const_iterator it = dpmToloadDpmMap.find(dpm);
    assert(it != dpmToloadDpmMap.end() && "not found??");
    return it->second;
  }
  inline void addLoadCVar(const DPIm &dpm, const CVar &loadVar) {
    typename DPMToCVarMap::iterator it = loadToPTCVarMap.find(dpm);
    if (it != loadToPTCVarMap.end())
      it->second = loadVar;
    else
      loadToPTCVarMap.insert(std::make_pair(dpm, loadVar));
  }
  inline const CVar &getLoadCVar(const DPIm &dpm) const {
    typename DPMToCVarMap::const_iterator it = loadToPTCVarMap.find(dpm);
    assert(it != loadToPTCVarMap.end() && "not found??");
    return it->second;
  }
  //@}
  /// Return Andersen's analysis
  inline AndersenWaveDiff *getAndersenAnalysis() const { return _ander; }
  /// handle out-of-budget queries
  //@{
  /// Handle out-of-budget dpm
  inline void handleOutOfBudgetDpm(const DPIm &dpm) {}
  inline bool testOutOfBudget(const DPIm &dpm) {
    if (outOfBudgetQuery)
      return true;
    if (++ddaStat->_NumOfStep > DPIm::getMaxBudget())
      outOfBudgetQuery = true;
    return isOutOfBudgetDpm(dpm) || outOfBudgetQuery;
  }
  inline bool isOutOfBudgetQuery() const { return outOfBudgetQuery; }
  inline void addOutOfBudgetDpm(const DPIm &dpm) {
    outOfBudgetDpms.insert(dpm);
  }
  inline bool isOutOfBudgetDpm(const DPIm &dpm) const {
    return outOfBudgetDpms.find(dpm) != outOfBudgetDpms.end();
  }
  //@}

  /// Set DDAStat
  inline DDAStat *setDDAStat(DDAStat *s) {
    ddaStat = s;
    return ddaStat;
  }
  /// stat strong updates num
  inline void addSUStat(const DPIm &dpm, const SVFGNode *node) {
    if (storeToDPMs[node].insert(dpm).second) {
      ddaStat->_NumOfStrongUpdates++;
      ddaStat->_StrongUpdateStores.set(node->getId());
    }
  }
  /// remove strong updates num if the dpm goes to weak updates branch
  inline void rmSUStat(const DPIm &dpm, const SVFGNode *node) {
    DPTItemSet &dpmSet = storeToDPMs[node];
    if (dpmSet.erase(dpm)) {
      ddaStat->_NumOfStrongUpdates--;
      if (dpmSet.empty())
        ddaStat->_StrongUpdateStores.reset(node->getId());
    }
  }

  bool outOfBudgetQuery;    ///< Whether the current query is out of step limits
  PAG *_pag;                ///< PAG
  SVFG *_svfg;              ///< SVFG
  AndersenWaveDiff *_ander; ///< Andersen's analysis
  NodeBS candidateQueries;  ///< candidate pointers;
  PTACallGraph *_callGraph; ///< CallGraph
  CallGraphSCC *_callGraphSCC; ///< SCC for CallGraph
  SVFGSCC *_svfgSCC;           ///< SCC for SVFG
  DPTItemSet backwardVisited;  ///< visited map during backward traversing
  DPImToCPtSetMap
      dpmToTLCPtSetMap; ///< points-to caching map for top-level vars
  DPImToCPtSetMap
      dpmToADCPtSetMap; ///< points-to caching map for address-taken vars
  LocToDPMVecMap locToDpmSetMap; ///< map location to its dpms
  DPMToDPMMap dpmToloadDpmMap;   ///< dpms at loads for may/must-alias analysis
                                 ///< with stores
  DPMToCVarMap loadToPTCVarMap;  ///< map a load dpm to its cvar pointed by its
                                 ///< pointer operand
  DPTItemSet outOfBudgetDpms;    ///< out of budget dpm set
  StoreToPMSetMap storeToDPMs;   ///< map store to set of DPM which have been
                                 ///< stong updated there
  DDAStat *ddaStat;              ///< DDA stat
  SVFGBuilder svfgBuilder;       ///< SVFG Builder
  NodeID curCandidate;           // [OS-CFI] hold current candidate node id
  NodeToStoreMap mapNodeStore;   // [OS-CFI] ToDo
  TargetToOriginContextMap mapTOrgCtx;               // [OS-CFI] ToDo
  SinkToOriginSensitiveTupleSetMap mapSOrgSenTupSet; // [OS-CFI] ToDo
  CallSwitchPairStack setCallStack;                  // [OS-CFI] ToDo
  SinkToCallStackMap mapCSSen;                       // [OS-CFI] ToDo
};

#endif /* VALUEFLOWDDA_H_ */
