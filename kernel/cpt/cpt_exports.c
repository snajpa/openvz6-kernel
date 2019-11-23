#include <linux/module.h>
#include <asm/signal.h>

#include <linux/cpt_obj.h>

EXPORT_SYMBOL(alloc_cpt_object);
EXPORT_SYMBOL(intern_cpt_object);
EXPORT_SYMBOL(insert_cpt_object);
EXPORT_SYMBOL(__cpt_object_add);
EXPORT_SYMBOL(cpt_object_add);
EXPORT_SYMBOL(cpt_object_get);
EXPORT_SYMBOL(lookup_cpt_object);
EXPORT_SYMBOL(lookup_cpt_obj_bypos);
