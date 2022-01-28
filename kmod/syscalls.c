/*******************************************************************
* Project:	ExecMon
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		syscalls.c
* Description:	This module responsibles for the linux kernel
*		syscall interpositioning.
*******************************************************************/

/*******************************************************************
* Includes
*******************************************************************/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include "includes/general.h"
#include "includes/mem.h"
#include "includes/syscalls.h"
#include "includes/comm.h"
#include "udis86.h"

/*******************************************************************
* Original Syscalls Prototypes
*******************************************************************/
asmlinkage long (*orig_sys_execve_fn)(const char __user * filename,
				const char __user * const __user * argv,
				const char __user * const __user * envp);

/*******************************************************************
* Name: 	obtain_sys_call_table_addr
* Description:	Obtains the address of the `sys_call_table` in the
*		system.
*******************************************************************/
static int obtain_sys_call_table_addr(unsigned long * sys_call_table_addr) {
	int ret = SUCCESS;
	unsigned long temp_sys_call_table_addr;

	temp_sys_call_table_addr = kallsyms_lookup_name(SYM_SYS_CALL_TABLE);
	
	/* Return error if the symbol doesn't exist */
	if (0 == sys_call_table_addr) {
		ret = ERROR;
		goto cleanup;
	}
	
	DBG_PRINT("Found sys_call_table: %p", (void *) temp_sys_call_table_addr);
	*sys_call_table_addr = temp_sys_call_table_addr;
		
cleanup:
	return ret;
}


/*******************************************************************
* Name:		new_sys_execve
* Description:	This function is called instead of sys_execve.
*		Our manipulation is quite simple at the moment,
*		we just send the execve parmeters to the user app.
*		Afterward, we call the original sys_execve.
*******************************************************************/
static asmlinkage long new_sys_execve(const char __user * filename,
				const char __user * const __user * argv,
				const char __user * const __user * envp) {
	size_t exec_line_size;
	char * exec_str = NULL;
	char ** p_argv = (char **) argv;
	char ktemp[1024];

	KLOG_PRINT("filename.length: [%ld]", strlen_user(filename));

	memset(ktemp, 0, sizeof(ktemp));
	if(strncpy_from_user(ktemp, filename, sizeof(ktemp)) >= 0) {
		KLOG_PRINT("ktemp [%s]", ktemp);
	} else {
		KLOG_PRINT("strncpy_user failed ...");
	}

    {
        /* get the number of arguments */
        int argc = 0;
        int i = 0;
        int kcmdline_size = 1024;
        char * kcmdline = vmalloc(kcmdline_size);
        memset(kcmdline, 0, kcmdline_size);
        if (argv) {
            while(1) {
                char * karg = NULL;
                unsigned long rv = -1;
                if((rv = copy_from_user(&karg, argv + i, sizeof(karg))) >= 0) {
                    if (NULL == karg) break;
                    KLOG_PRINT("arg[%d] [%p]", i, karg);
                    i++;
                    memset(ktemp, 0, sizeof(ktemp));
                    if(strncpy_from_user(ktemp, (const char __user *)karg, sizeof(ktemp)) >= 0) {
		                KLOG_PRINT("arg[%d] [%s]", i, ktemp);
		                strncat(kcmdline, ktemp, strlen(ktemp));
		                strncat(kcmdline, " ", strlen(" "));
                    } else {
		                KLOG_PRINT("strncpy_from_user: failed");
                    }
                } else {
                    KLOG_PRINT("copy_from_user: failed for arg [%d]", i);
                }
            }
        }

        argc = i;
        if (argc > 0) {
            /* account for the space that is being appended */
            int cmdline_length = strlen(kcmdline) - 1;
            KLOG_PRINT("cmdline_length [%d]", cmdline_length);
            kcmdline[cmdline_length] = '\0';
        }
        KLOG_PRINT("total arguments - argc [%d]", argc);
        KLOG_PRINT("kcmdline [%s]", kcmdline);
        if (kcmdline) vfree(kcmdline);
    }

	{
        char ** kargv = NULL;
        unsigned long rv = -1;
        if((rv = copy_from_user(&kargv, argv, sizeof(kargv))) >= 0) {
            KLOG_PRINT("kargv [%p]", kargv);
            memset(ktemp, 0, sizeof(ktemp));
            if(strncpy_from_user(ktemp, (const char __user *)kargv, sizeof(ktemp)) >= 0) {
		        KLOG_PRINT("arg0 [%s]", ktemp);
            } else {
		        KLOG_PRINT("strncpy_from_user: failed");
            }
        } else {
            KLOG_PRINT("copy_from_user: failed ...");
        }
	}
	return orig_sys_execve_fn(filename, argv, envp);

	exec_line_size = (strlen(filename) + 1);

	/* Iterate through the execution arguments, to determine the final
	size of the execution string. */
	while (NULL != *p_argv) {
		exec_line_size += (strlen(*p_argv) + 1);
		(char **) p_argv++;	
	}
	
	/* Allocate enough memory for the execution string */
	exec_str = vmalloc(exec_line_size);
	if (NULL != exec_str) {
		snprintf(exec_str, exec_line_size, "%s", filename);

		/* Iterate through the execution arguments */
		p_argv = (char **) argv;
		while (NULL != *p_argv) {
			/* Concatenate each argument with our execution line */
			snprintf(exec_str, exec_line_size,
					"%s %s", exec_str, *p_argv);
			(char **) p_argv++;	
		}

		/* Send execution line to the user app */
		COMM_nl_send_exec_msg(exec_str);
	}


	/* Finally, call the original sys_execve */
	return orig_sys_execve_fn(filename, argv, envp);

}

/*******************************************************************
* Name:		hook_sys_execve
* Description:	This function patches the memory of stub_execve,
*		replacing the call to sys_execve with a call
*		to our new_sys_execve function.
*******************************************************************/
static int hook_sys_execve(unsigned long sys_call_table_addr) {
	int ret = SUCCESS;
	unsigned long orig_stub_execve_addr;
	unsigned long orig_call_addr;

	/* Get stub_execve address */
	orig_stub_execve_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_execve];

	/* Patch the relative call instruction.
	 * Replace sys_execve with new_sys_execve */
	ret = MEM_patch_relative_call(orig_stub_execve_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) new_sys_execve, &orig_call_addr);
	if (SUCCESS != ret) {
		goto cleanup;
	}

	/* Backup the original sys_execve address */
	orig_sys_execve_fn = (void * ) orig_call_addr;

cleanup:
	return ret;
}

/*******************************************************************
* Name:		remove_hook_sys_execve
* Description:	This function patches the memory of stub_execve,
*		replacing the call to the new execve, with the old
*		sys_execve.
*******************************************************************/
static void remove_hook_sys_execve(unsigned long sys_call_table_addr) {
	unsigned long orig_stub_execve_addr;

	/* Get stub_execve address */
	orig_stub_execve_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_execve];

	/* Patch the relative call instruction.
	 * Replace new_sys_execve with the original sys_execve */
	MEM_patch_relative_call(orig_stub_execve_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) orig_sys_execve_fn, NULL);
}



/*******************************************************************
* Name:		SYSCALLS_set_hooks()
* Description:	Sets hooks on specific syscalls in the system.
*******************************************************************/
int SYSCALLS_set_hooks(void)
{
	int ret = SUCCESS;
	int call_rv;
	unsigned long sys_call_table_addr;

	DBG_PRINT("Setting syscalls hooks");
	
	/* Obtain syscall table address */
	call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != call_rv) {
		ret = call_rv;
		goto cleanup;
	}

	/* Fix stub_execve to call our new execve function */
	hook_sys_execve(sys_call_table_addr);

cleanup:
	return ret;
}

/*******************************************************************
* Name:		SYSCALLS_remove_hooks()
* Description:	Removes hooks from specific syscalls in the system.
*******************************************************************/
int SYSCALLS_remove_hooks(void)
{
	int ret = SUCCESS;
	int call_rv;
	unsigned long sys_call_table_addr;

	DBG_PRINT("Removing syscalls hooks");
	
	/* Obtain syscall table address */
	call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != call_rv) {
		ret = call_rv;
		goto cleanup;
	}

	/* Fix stub_execve to call the original execve function */
	remove_hook_sys_execve(sys_call_table_addr);

cleanup:
	return ret;


}

