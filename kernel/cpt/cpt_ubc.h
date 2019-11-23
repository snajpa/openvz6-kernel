#ifdef CONFIG_BEANCOUNTERS
cpt_object_t *cpt_add_ubc(struct user_beancounter *bc, struct cpt_context *ctx);
__u64 cpt_lookup_ubc(struct user_beancounter *bc, struct cpt_context *ctx);
int cpt_dump_ubc(struct cpt_context *ctx);

struct user_beancounter *rst_lookup_ubc(__u64 pos, struct cpt_context *ctx);
int rst_undump_ubc(struct cpt_context *ctx);

void cpt_finish_ubc(struct cpt_context *ctx);
void rst_finish_ubc(struct cpt_context *ctx);

static inline void set_ubc_unlimited(struct cpt_context *ctx,
				     struct user_beancounter *bc)
{
	int i;

	spin_lock_irq(&bc->ub_lock);
	for ( i = 0 ; i < UB_RESOURCES ; i++ ) {
		ctx->saved_ubc[i] = bc->ub_parms[i];
		bc->ub_parms[i].barrier = bc->ub_parms[i].limit = UB_MAXVALUE;
	}
	spin_unlock_irq(&bc->ub_lock);
}

static inline void restore_ubc_limits(struct cpt_context *ctx,
				      struct user_beancounter *bc)
{
	int i;

	spin_lock_irq(&bc->ub_lock);
	for ( i = 0 ; i < UB_RESOURCES ; i++ ) {
		bc->ub_parms[i].barrier = ctx->saved_ubc[i].barrier;
		bc->ub_parms[i].limit   = ctx->saved_ubc[i].limit;
		bc->ub_parms[i].maxheld = max(ctx->saved_ubc[i].maxheld,
					      bc->ub_parms[i].maxheld);
		bc->ub_parms[i].minheld = min(ctx->saved_ubc[i].minheld,
					      bc->ub_parms[i].minheld);
		bc->ub_parms[i].failcnt = max(ctx->saved_ubc[i].failcnt,
					      bc->ub_parms[i].failcnt);
	}
	spin_unlock_irq(&bc->ub_lock);
}

#else
static int inline cpt_dump_ubc(struct cpt_context *ctx)
{ return 0; }
static int inline rst_undump_ubc(struct cpt_context *ctx)
{ return 0; }
static void inline cpt_finish_ubc(struct cpt_context *ctx)
{ return; }
static void inline rst_finish_ubc(struct cpt_context *ctx)
{ return; }
#endif

