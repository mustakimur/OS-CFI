/*
 * @file: DDAPass.h
 * @author: Yulei Sui
 * @date: 01/07/2014
 * @version: 1.0
 *
 */


#ifndef WPA_H_
#define WPA_H_

#include "MemoryModel/PointerAnalysis.h"
#include "DDA/DDAClient.h"
#include "Util/SCC.h"
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Pass.h>

class SVFG;
class SVFGEdge;

/*!
 * Demand-Driven Pointer Analysis.
 * This class performs various pointer analysis on the given module.
 */
class DDAPass: public llvm::ModulePass {

public:
    /// Pass ID
    static char ID;
    typedef SCCDetection<SVFG*> SVFGSCC;
    typedef std::set<const SVFGEdge*> SVFGEdgeSet;
    typedef std::vector<PointerAnalysis*> PTAVector;

    DDAPass() : llvm::ModulePass(ID), _pta(NULL), _client(NULL) {}
    ~DDAPass();

    virtual inline void getAnalysisUsage(llvm::AnalysisUsage &au) const {
        // declare your dependencies here.
        /// do not intend to change the IR in this pass,
        au.setPreservesAll();
    }

    virtual inline void* getAdjustedAnalysisPointer(llvm::AnalysisID id) {
        return this;
    }

    /// Interface expose to users of our pointer analysis, given Location infos
    virtual inline llvm::AliasResult alias(const llvm::MemoryLocation &LocA, const llvm::MemoryLocation &LocB) {
        return alias(LocA.Ptr, LocB.Ptr);
    }

    /// Interface expose to users of our pointer analysis, given Value infos
    virtual llvm::AliasResult alias(const llvm::Value* V1,	const llvm::Value* V2);

    /// We start from here
    virtual bool runOnModule(SVFModule module);

    /// We start from here
    virtual bool runOnModule(llvm::Module& module) {
        return runOnModule(module);
    }

    /// Select a client
    virtual void selectClient(SVFModule module);

    /// Pass name
    virtual inline llvm::StringRef getPassName() const {
        return "DDAPass";
    }

private:
    /// Print queries' pts
    void printQueryPTS();
    /// Create pointer analysis according to specified kind and analyze the module.
    void runPointerAnalysis(SVFModule module, u32_t kind);
    /// Initialize queries for DDA
    void answerQueries(PointerAnalysis* pta);
    /// Context insensitive Edge for DDA
    void initCxtInsensitiveEdges(PointerAnalysis* pta, const SVFG* svfg,const SVFGSCC* svfgSCC, SVFGEdgeSet& insensitveEdges);
    /// Return TRUE if this edge is inside a SVFG SCC, i.e., src node and dst node are in the same SCC on the SVFG.
    bool edgeInSVFGSCC(const SVFGSCC* svfgSCC,const SVFGEdge* edge);
    /// Return TRUE if this edge is inside a SVFG SCC, i.e., src node and dst node are in the same SCC on the SVFG.
    bool edgeInCallGraphSCC(PointerAnalysis* pta,const SVFGEdge* edge);

    void collectCxtInsenEdgeForRecur(PointerAnalysis* pta, const SVFG* svfg,SVFGEdgeSet& insensitveEdges);
    void collectCxtInsenEdgeForVFCycle(PointerAnalysis* pta, const SVFG* svfg,const SVFGSCC* svfgSCC, SVFGEdgeSet& insensitveEdges);

    PointerAnalysis* _pta;	///<  pointer analysis to be executed.
    DDAClient* _client;		///<  DDA client used

};


#endif /* WPA_H_ */
