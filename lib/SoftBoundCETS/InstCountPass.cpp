///=== SoftBound/InstCountPass.cpp --*- C++ -*=====///
// Pointer based Spatial and Temporal Memory Safety Pass
//Copyright (c) 2011 Santosh Nagarakatte, Milo M. K. Martin. All rights reserved.

// Developed by: Santosh Nagarakatte, Milo M.K. Martin,
//               Jianzhou Zhao, Steve Zdancewic
//               Department of Computer and Information Sciences,
//               University of Pennsylvania
//               http://www.cis.upenn.edu/acg/softbound/

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal with the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimers.

//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimers in the
//      documentation and/or other materials provided with the distribution.

//   3. Neither the names of Santosh Nagarakatte, Milo M. K. Martin,
//      Jianzhou Zhao, Steve Zdancewic, University of Pennsylvania, nor
//      the names of its contributors may be used to endorse or promote
//      products derived from this Software without specific prior
//      written permission.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// WITH THE SOFTWARE.
//===---------------------------------------------------------------------===//

#include "SoftBound/InstCountPass.h"

char InstCountPass:: ID = 0;

static RegisterPass<InstCountPass> P ("InstCountPass", "Adds handlers to count specific instructions");


void InstCountPass:: initializeHandlers(Module & module){

  Type* void_ty = Type::getVoidTy(module.getContext());
  m_loadchecks_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_loadchecks",
								    void_ty, NULL));
  
  m_storechecks_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_storechecks",
								     void_ty, NULL));
  
  m_pointerloads_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_pointerloads",
								      void_ty, NULL));
  
  m_pointerstores_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_pointerstores",
								       void_ty, NULL));
  
  m_memcopychecks_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_memcopychecks",
								       void_ty, NULL));

  m_shadowstack_stores_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_shadowstack_loads",
									    void_ty, NULL));

  m_shadowstack_loads_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_shadowstack_stores",
									   void_ty, NULL));
  
  m_indirectcallchecks_func = dyn_cast<Function>(module.getOrInsertFunction("__sbcets_stats_indirectcallchecks",
									    void_ty, NULL));



}

void 
InstCountPass::insertHandler(Function* func_to_insert, 
			     Instruction* insert_at){

  SmallVector<Value*, 8> args;
  
  CallInst::Create(func_to_insert, args, "", insert_at);
  return;
}

bool InstCountPass:: runOnModule(Module & module){
  
  initializeHandlers(module);

  for(Module::iterator ff_begin = module.begin(), ff_end = module.end();
      ff_begin != ff_end; ++ff_begin){

    Function* func = dyn_cast<Function>(ff_begin);
    assert(func && "Not a function?");

    if(func->isDeclaration()|| func->isVarArg()){
      continue;
    }
    
    for(Function::arg_iterator ib = func->arg_begin(), ie = func->arg_end();
	ib != ie; ++ib){
      if(isa<PointerType>(ib->getType())){
	Instruction* insert_at = dyn_cast<Instruction>(func->begin()->begin());
	insertHandler(m_shadowstack_loads_func, insert_at);	
      }      
    }
    
    for(Function::iterator bb_begin =  func->begin(), bb_end = func->end();
	bb_begin != bb_end; ++bb_begin){
      
      BasicBlock* bb = dyn_cast<BasicBlock>(bb_begin);
      for(BasicBlock::iterator ins_begin = bb->begin(), ins_end = bb->end();
	  ins_begin != ins_end; ++ins_begin){
	
	Instruction* inst = dyn_cast<Instruction>(ins_begin);

	switch(inst->getOpcode()){
	case Instruction::Load:
	  {
	    if(isa<PointerType>(inst->getType())){
	      insertHandler(m_pointerloads_func, inst);
	    }
	    insertHandler(m_loadchecks_func, inst);
	  }
	  break;
	  
	case Instruction::Store:
	  {
	    Value* store_operand = inst->getOperand(0);
	    if(isa<PointerType>(store_operand->getType())){
	      insertHandler(m_pointerstores_func, inst);
	    }
	    insertHandler(m_storechecks_func, inst);	    
	  }
	  break;

	case Instruction::Call:
	  {
	    CallInst* call_inst = dyn_cast<CallInst>(inst);

	    CallSite cs(call_inst);
	    for(unsigned i = 0; i < cs.arg_size(); i++){
	      Value* arg_value = cs.getArgument(i);
	      if(isa<PointerType>(arg_value->getType())){
		insertHandler(m_shadowstack_stores_func, call_inst);
	      }
	    }
	    
	    if(isa<PointerType>(call_inst->getType())){
	      insertHandler(m_shadowstack_loads_func, call_inst);
	    }
	    
	    Function* call_func = call_inst->getCalledFunction();
	    if(call_func && (call_func->getName().find("llvm.memcpy") == 0)){
	      insertHandler(m_memcopychecks_func, call_inst);
	    }	    
	  }
	  break;
	default:
	  break;

	} // switch case ends

      } //iterating over instructions

    } //iterating over basic block ends 
    
  } // iterating over a module
  return true;
}
