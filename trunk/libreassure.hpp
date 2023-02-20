#ifndef LIBREASSURE_HPP
#define LIBREASSURE_HPP

#include "threadstate.hpp"


/**
 * Enum for returning results of reassure handling a particular exception
 */
typedef enum REASSURE_EHANDLING_RESULT { 
	RHR_HANDLED, //!< Exception handled
	RHR_RESCUED,  //!< Exception handled and proccess rescued
	RHR_ERROR  //!< Exception handling error, or exception cannot be handled
} reassure_ehandling_result_t;

//! Enum defining types of checkpoints
enum CHECKPOINT_TYPES { UNKNOWN_CHECKP = 0, WLOG_CHECKP, FORK_CHECKP };
//! Type of checkpoint used for rolling back memory contents
typedef enum CHECKPOINT_TYPES checkp_t;

//! Code executing in this version returns to the correct one
#define AUTOCORRECT_VERSION	0
//! Code in this version executes "normally"
#define NORMAL_VERSION 		1
//! Code in this version performs checkpointing
#define CHECKPOINT_VERSION	2



//! Global holding type of checkpointing used
extern checkp_t checkpoint_type;

//! Global register that holds the currect code cache version
extern REG version_reg;



int reassure_init(const char *conf_fn, BOOL rb, checkp_t ctype);

void reassure_rollback(struct thread_state *ts, CONTEXT *ctx, ADDRINT new_pc);

reassure_ehandling_result_t reassure_handle_fault(THREADID tid, INT32 sig, 
		CONTEXT *ctx, BOOL hasHandler, 
		const EXCEPTION_INFO *pExceptInfo);

reassure_ehandling_result_t reassure_handle_internal_fault(THREADID tid, 
		EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pctx, 
		CONTEXT *ctx);

#endif
