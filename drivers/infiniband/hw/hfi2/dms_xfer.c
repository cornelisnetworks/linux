// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2026 - Cornelis Networks, Inc.
 *
 * DMS transfer engine: protocol handlers, ring/keyring primitives, packet
 * injection (PIO/SDMA), poll loops and TID-set management.
 */
void _ring_init(struct hfi2_dms_ring *ring, u32 arr_size_lg2, u32 max_size)
{
	DMS_BUG_ON(!ring);

	/*
	 * The ring masks backing-array indices with (1 << arr_size_lg2) - 1, so
	 * the caller's backing array MUST hold 1 << arr_size_lg2 entries, not
	 * merely max_size. Callers size the order as const_ilog2(max_size) + 1;
	 * the +1 both provides the sentinel slot that distinguishes empty from
	 * full (max_size < mask, asserted below) and guarantees the backing
	 * array is large enough that a masked index can never run off the end
	 * once head/tail advance past max_size.
	 */
	u64 const mask = (1ull << arr_size_lg2) - 1ull;

	/* max_size < mask reserves the sentinel slot (empty vs full). */
	DMS_BUG_ON(max_size >= mask);

	ring->head = 0;
	ring->tail = 0;
	ring->mask = mask;
	ring->max_size = max_size;
}

static u32 _ring_max_size(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->max_size;
}

u32 _ring_size(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->tail - ring->head;
}

static u32 _ring_free(struct hfi2_dms_ring *ring)
{
	return _ring_max_size(ring) - _ring_size(ring);
}

static bool _ring_empty(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->head == ring->tail;
}

static u32 _ring_tail(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	DMS_BUG_ON(_ring_empty(ring));
	return (ring->tail - 1) & ring->mask;
}

static u32 _ring_head(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	DMS_BUG_ON(_ring_empty(ring));
	return ring->head & ring->mask;
}

static u32 _ring_index(struct hfi2_dms_ring *ring, u32 pos)
{
	DMS_BUG_ON(pos > _ring_size(ring));
	return (ring->head + pos) & ring->mask;
}

// adds the element to the ring, then returns the _index_ of that element
static u32 _ring_produce(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_free(ring) == 0);
	return (ring->tail++) & ring->mask;
}

static u32 _ring_produce_front(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_free(ring) == 0);
	ring->head -= 1;
	return ring->head & ring->mask;
}

// returns the _index_ of the first element in the ring, then removes that element
u32 _ring_consume(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_empty(ring));
	return (ring->head++) & ring->mask;
}


void _rift_keyring_init(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	_ring_init(&keyring->ring, HFI2_DMS_RIFT_IDX_BITS+1, HFI2_DMS_RIFT_IDX_SIZE);
}

void _rift_keyring_add(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_free(&keyring->ring) == 0);
	u32 const idx = _ring_produce(&keyring->ring);
	keyring->arr[idx] = key;
}

void _rift_keyring_add_front(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_free(&keyring->ring) == 0);
	u32 const idx = _ring_produce_front(&keyring->ring);
	keyring->arr[idx] = key;
}

u64 _rift_keyring_size(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	return _ring_size(&keyring->ring);
}

bool _rift_keyring_empty(struct hfi2_dms_rift_keyring *keyring)
{
	return _ring_empty(&keyring->ring);
}

hfi2_dms_rift_key_t _rift_keyring_tail(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_empty(&keyring->ring));
	u32 const idx = _ring_tail(&keyring->ring);
	return keyring->arr[idx];
}

hfi2_dms_rift_key_t _rift_keyring_head(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_empty(&keyring->ring));
	u32 const idx = _ring_head(&keyring->ring);
	return keyring->arr[idx];
}

hfi2_dms_rift_key_t _rift_keyring_peek(struct hfi2_dms_rift_keyring *keyring)
{
	return _rift_keyring_head(keyring);
}

hfi2_dms_rift_key_t _rift_keyring_at(struct hfi2_dms_rift_keyring *keyring, u32 pos)
{
	DMS_BUG_ON(!keyring);
	u32 const idx = _ring_index(&keyring->ring, pos);
	return keyring->arr[idx];
}

void _rift_keyring_set(struct hfi2_dms_rift_keyring *keyring, u64 pos, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	u32 const idx = _ring_index(&keyring->ring, pos);
	keyring->arr[idx] = key;
}

void _rift_keyring_advance(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	_ring_consume(&keyring->ring);
}

bool _rift_keyring_remove(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	// PRE - no duplicate ring entries
	DMS_BUG_ON(!keyring);
	u64 const count = _rift_keyring_size(keyring);

	if (count == 0)
		return false;

	if (_rift_keyring_head(keyring).value == key.value) {
		// special case: remove from head
		keyring->ring.head += 1;
		return true;
	}

	if (_rift_keyring_tail(keyring).value == key.value) {
		// special case: remove from tail
		keyring->ring.tail -= 1;
		return true;
	}

	// general case: remove from middle; must iterate entire ring in order to "compact" the ring after
	// potentially removing a middle entry.

	u64 cancel = 0;
	for (u64 i = 0; i < count; ++i) {
		hfi2_dms_rift_key_t const cur = _rift_keyring_at(keyring, i);
		if (cur.value == key.value) {
			cancel += 1;
		} else {
			_rift_keyring_set(keyring, i - cancel, cur);
		}
	}
	keyring->ring.tail -= cancel;

	return cancel > 0;
}

static void _tidset_free_then_poll_waiters(struct hfi2_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);

	/*
	 * Return the speculative-budget unit at the tidset's true FREE
	 * transition -- the only point the pool can actually re-hand this
	 * tidset out. Doing it here (not at cancel or fallback) keeps
	 * spec_tidsets_available from ever exceeding the real free count.
	 */
	if (dms->read_requests[tid_set].spec_charged) {
		dms->spec_tidsets_available += 1;
		dms->read_requests[tid_set].spec_charged = false;
	}

	/* Always release to global free stack (caller may have already set state FREE) */
	_tidset_idx_release(dms, tid_set);

	dms->read_requests[tid_set].state = HFI2_DMS_TIDSET_STATE_FREE;

	_service_global_tidset_waiters(dms);

	if (dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_FREE) {
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
	}
}

static int _eager_rx_copy_prefix(struct hfi2_dms_rx_tracker *rx_tracker,
				 enum hfi2_dms_msg_type msg_type,
				 void *hbuf, void *ebuf, u32 prefix_bytes)
{
	u32 const inline_max = 120 - (_msgtype_wire_payload_offset[msg_type] - 8);
	u32 const hdrq_copy = min(prefix_bytes, inline_max);
	u32 const ebuf_copy = prefix_bytes - hdrq_copy;
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	int ret;

	ret = (pp->memcpy)(pp, rx_tracker->rbuf_start_offset, hdrq_copy, hbuf,
			 false);
	if (ret != 0)
		return -EIO;

	if (ebuf_copy > 0) {
		if (DMS_WARN_ON(!ebuf))
			return -EINVAL;
		ret = (pp->memcpy)(pp, rx_tracker->rbuf_start_offset + hdrq_copy,
				 ebuf_copy, ebuf, false);
		if (ret != 0)
			return -EIO;
	}
	return 0;
}

/*
 * Eager-only WRITE_START: copy @nbytes of the payload at @payload to the start
 * of the destination with a single copy.  @payload is in the eager buffer
 * (WRITE_START_EAGER, ebuf + WSE_EBUF_PAYLOAD_OFFSET) or in the header queue
 * (WRITE_START_TINY).
 */
static int _wse_rx_copy(struct hfi2_dms_rx_tracker *rx_tracker,
			void *payload, u32 nbytes)
{
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	int ret;

	/* Explicit dereference: memcpy may be a function-like macro. */
	ret = (*pp->memcpy)(pp, rx_tracker->rbuf_start_offset, nbytes, payload,
			    false);
	return ret ? -EIO : 0;
}

/*
 * Returns true in two distinct senses: an empty inflight_bitmap means the
 * caller has no in-flight peer tidset to align with, so *entropy is a fresh
 * round-robin pick (not an inherited value); a non-empty bitmap returns true
 * only when every in-flight tidset shares one saved_entropy, in which case
 * *entropy is that shared value. false means in-flight tidsets disagree.
 * Callers that gate on tidsets_in_use > 0 before invoking this (guaranteeing
 * inflight_bitmap != 0, since the two are always kept in lockstep by
 * _dms_rx_tracker_tidset_inflight_set/_clear) only ever observe the
 * shared-or-disagree outcome, never the fresh-pick branch.
 */
static bool _dms_read_requests_inflight_entropy_narrowed(struct hfi2_dms *dms,
							 u64 inflight_bitmap, u16 *entropy)
{
	unsigned int pos;
	u16 prev_entropy;

	if (inflight_bitmap == 0) {
		*entropy = _dms_entropy_next(dms);
		return true;
	}

	pos = __ffs64(inflight_bitmap);
	prev_entropy = dms->read_requests[pos].saved_entropy;
	inflight_bitmap ^= (1ULL << pos);

	while (inflight_bitmap) {
		pos = __ffs64(inflight_bitmap);
		if (prev_entropy != dms->read_requests[pos].saved_entropy)
			return false;
		inflight_bitmap ^= (1ULL << pos);
	}

	*entropy = prev_entropy;
	return true;
}

/*
 * True if any of @rx_tracker's in-flight tidsets has bounce edges. Those
 * edges reach the destination only when software copies them out at the
 * tidset's completion, after every byte hardware placed for it -- so a
 * chained child riding the same SDMA engine behind this tidset could land
 * its own bytes first and then be overwritten by the copy-out. Early READ
 * release must wait until no such tidset is in flight.
 */
static bool _rx_tracker_inflight_has_bounce(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker const *rx_tracker)
{
	u64 bitmap = rx_tracker->tidsets_inflight_bitmap;

	while (bitmap) {
		unsigned int const pos = __ffs64(bitmap);

		if (dms->read_requests[pos].has_bounce)
			return true;
		bitmap &= bitmap - 1;
	}
	return false;
}

static int _dms_rx_rift_continue_read_data(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	hfi2_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->rift, local_rift_key) == NULL) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	/*
	 * Bilateral promote: fire on the initiator side just before
	 * READ_START goes on the wire, mirroring the responder-side
	 * fire in hfi2_dms_impl_handle_read_start. The callback is a
	 * non-blocking hint that this MR is now hot; NULL-safe for
	 * providers without proactive pinning (verbs, etc.).
	 */
	if (rx_tracker->page_provider.promote)
		rx_tracker->page_provider.promote(rx_tracker->page_provider.provider_ctx);

	/*
	 * Speculative TID is the preferred protocol if all conditions are satisfied.
	 */
	if (bulksvc_spec_tid_enabled && _spec_tid_read_eligible(rx_tracker)) {
		if (rx_tracker->hdr.parent_handle.value == 0) {
			rx_tracker->hdr.entropy = _dms_entropy_next(dms);
			if (_spec_tid_read_start(dms, rx_tracker))
				return 0;
		} else { /* chaining */
			union hfi2_dms_tracker *parent =
				_handle_to_tracker(rx_tracker->hdr.parent_handle);
			struct hfi2_dms_transfer_handle child_h =
				_tracker_to_handle((union hfi2_dms_tracker *)rx_tracker);

			if (!parent || parent->hdr.child_handle.value != child_h.value) {
				/* Parent retired between bind and gate, or link broken */
				dms->counters.chain_null_handle += (!parent);
				rx_tracker->hdr.parent_handle =
					HFI2_DMS_TRANSFER_HANDLE_NONE;
				rx_tracker->hdr.entropy = _dms_entropy_next(dms);
				if (_spec_tid_read_start(dms, rx_tracker))
					return 0;

			/* The parent has requested all of its payload. */
			} else if (parent->hdr.op == HFI2_DMS_XFER_OP_READ &&
					!_rx_tracker_is_eager(&parent->rx) &&
					parent->rx.sbuf_cursor >= parent->rx.total_payload &&
					!_rx_tracker_inflight_has_bounce(dms, &parent->rx)) {
				union hfi2_dms_tracker *child =
					(union hfi2_dms_tracker *)rx_tracker;
				u64 bitmap = parent->rx.tidsets_inflight_bitmap;
				u16 *entropy = &rx_tracker->hdr.entropy;
				bool narrowed;

				narrowed = _dms_read_requests_inflight_entropy_narrowed(dms, bitmap,
											entropy);
				if (narrowed && _spec_tid_read_start(dms, rx_tracker)) {
					_tracker_detach_from_parent(dms, child);
					/*
					 * Inherited entropy only needs to order
					 * this burst behind the parent's
					 * remaining requests, not any later
					 * request this child makes on its own.
					 * Same-engine FIFO + GBN guarantee the
					 * parent's remaining data is delivered
					 * before this child's own residual
					 * DATA_REQUESTs can fire, so clear the
					 * inherited-entropy flag now: any
					 * residual request is free to rotate to
					 * a fresh engine instead of pinning to
					 * the parent's.
					 */
					child->rx.chain_inherit_valid = false;
					return 0;
				}
			}
		}
	}
	rx_tracker->hdr.entropy = 0;

	/* Park only if READ_START is this child's gate; the gate also self-starts
	 * (and severs links) for an already-released child bound elsewhere. */
	if (_tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
			  HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START)) {
		dms->counters.chain_parked_read++;
		return 0; /* parked: RIFT slot retained, no inject */
	}

	/* RIFT entry is assigned; inject READ_START and wait for the DATA_START response. */
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START);

	return hfi2_dms_impl_inject_read_start(dms, rx_tracker, NULL, 0,
					       HFI2_DMS_MSG_TYPE_READ_START);
}

static void _dms_rx_tracker_tidset_inflight_set(struct hfi2_dms_rx_tracker *rx_tracker,
						u32 const tidset_idx)
{
	if (WARN_ON_ONCE(!rx_tracker))
		return;
	if (WARN_ON_ONCE(tidset_idx >= HFI2_DMS_TID_SET_IDX_COUNT))
		return;
	if (WARN_ON_ONCE(rx_tracker->tidsets_in_use > HFI2_DMS_TRACKER_TIDSET_MAX))
		return;
	if (WARN_ON_ONCE(!!(rx_tracker->tidsets_inflight_bitmap & (1ULL << tidset_idx))))
		return;

	rx_tracker->tidsets_inflight_bitmap ^= (1ULL << tidset_idx);
	rx_tracker->tidsets_in_use += 1;
}

static void _dms_rx_tracker_tidset_inflight_clear(struct hfi2_dms_rx_tracker *rx_tracker,
						  u32 const tidset_idx)
{
	if (WARN_ON_ONCE(!rx_tracker))
		return;
	if (WARN_ON_ONCE(tidset_idx >= HFI2_DMS_TID_SET_IDX_COUNT))
		return;
	if (WARN_ON_ONCE(!rx_tracker->tidsets_in_use))
		return;
	if (WARN_ON_ONCE(!(rx_tracker->tidsets_inflight_bitmap & (1ULL << tidset_idx))))
		return;

	rx_tracker->tidsets_inflight_bitmap ^= (1ULL << tidset_idx);
	rx_tracker->tidsets_in_use -= 1;
}

static int _dms_rx_rift_continue_write_start(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, void *hbuf, void *ebuf, u32 const eager_nbytes)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	int err = 0;
	hfi2_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;

	if (_rift_key_error(local_rift_key) != HFI2_DMS_RIFT_ERR_KEYLESS) {
		DMS_BUG_ON(_rift_key_error(local_rift_key));

		if (!_rift_lookup(&dms->rift, local_rift_key)) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "(%d) Ignore invalid rx rift key 0x%04x (%u %u)\n",
				   __LINE__, local_rift_key.value,
				   _rift_key_generation(local_rift_key),
				   _rift_key_index(local_rift_key));
			return 0;
		}
	}

	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

	if (rx_tracker->payload_remaining == 0) {
		/* Complete using fence only. */

		dms->counters.eager_rx++;
		goto completed_success;
	}

	if (hbuf) {
		/*
		 * Eager: the packet carries the first eager_nbytes of the
		 * payload, or all of it. Land that prefix by CPU and request
		 * the rest.
		 */
		u32 const prefix = min_t(u32, rx_tracker->total_payload,
					 eager_nbytes);

		err = _wse_rx_copy(rx_tracker, hbuf, prefix);
		if (err != 0)
			goto completed_error;

		dms->counters.eager_rx++;
		rx_tracker->hdr.byte_odometer += prefix;
		rx_tracker->payload_remaining -= prefix;
		if (rx_tracker->payload_remaining == 0)
			goto completed_success;

		rx_tracker->sbuf_cursor = prefix;
	}

	/*
	 * The tidsets request the payload not yet delivered; any sub-quadword
	 * edges, the start or end of the buffer included, land through the
	 * tidset bounce page.
	 */
	_dms_rx_issue_data_request_burst(dms, rx_tracker, false);
	return 0;

completed_success:
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, true);
	return 0;

completed_error:
	rx_tracker->payload_remaining = 0;
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, err, true);
	return 0;
}

int hfi2_dms_read_data(struct hfi2_dms *dms,
		enum hfi2_dms_fabric_port_idx port_idx, u32 src_lid,
		union hfi2_dms_key dms_key, u64 key_offset_or_vaddr, u32 size,
		struct hfi2_dms_page_provider page_provider, u64 mr_offset,
		u16 flags, u64 submit_flags, u64 imm_data,
		struct hfi2_dms_completion const completion,
		u64 const order_key,
		struct hfi2_dms_transfer_handle parent_handle,
		struct hfi2_dms_transfer_handle *out_handle)
{
	int ret;
	u64 start, end;
	u64 starting_rbuf_offset;
	struct hfi2_dms_rx_tracker *rx_tracker;

	if (WARN_ON_ONCE(!dms))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.resolve_start))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.provider_ctx))
		return -EFAULT;
	if (WARN_ON(src_lid == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(size == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(port_idx >= dms->dd->num_pports))
		return -EINVAL;

	start = dms_rdtsc();
	dms->counters.sending_first_rr = ktime_get();

	if (ppd_same_hfi(&dms->dd->pport[port_idx], src_lid)) {
		if (!dms->dd->loopback_enabled)
			return -EOPNOTSUPP;
		port_idx = loopback_pidx_dd(dms->dd, port_idx);
		if (!dms->port_available[port_idx])
			return -EOPNOTSUPP;
	}

	if (!dms->port_available[port_idx])
		return -ENOLINK;

	ret = page_provider.resolve_start(&page_provider, mr_offset, size,
					  &starting_rbuf_offset);
	if (ret < 0)
		return ret; // Unable to start rdma read bulk transfer operation

	rx_tracker = hfi2_dms_impl_rx_tracker_read_new(dms, port_idx, size,
			key_offset_or_vaddr, dms_key,
			_dms_initiator_peer(dms, src_lid, submit_flags),
			page_provider, starting_rbuf_offset, flags,
			submit_flags, imm_data, &completion, order_key);
	if (rx_tracker == NULL)
		return -ENOMEM;
	
	/* Bind: link child to parent and choose where it will park. */
	_tracker_bind(dms, (union hfi2_dms_tracker *)rx_tracker, parent_handle);

	dms_trace(dms_read_data, dms,
		  _tracker_to_handle((union hfi2_dms_tracker *)rx_tracker).value,
		  port_idx, src_lid, dms_key, key_offset_or_vaddr, size,
		  mr_offset, flags, submit_flags, imm_data, order_key);

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)rx_tracker);
	if (ret < 0) {
		_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		return ret;
	}
	if (ret > 0) {
		rx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_INITIATOR].ticker_total;
		ret = _dms_rx_rift_continue_read_data(dms, rx_tracker);
		if (ret < 0) {
			/* Sever parent link before recycle. */
			_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
			_rift_release(&dms->rift, rx_tracker->hdr.local_rift_key);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			return ret;
		}
	}

	if (out_handle)
		*out_handle = _tracker_to_handle((union hfi2_dms_tracker *)rx_tracker);

	end = dms_rdtsc();
	dms->counters.rget += end - start;

	return 0;
}

static void _tracker_rift_release(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, struct hfi2_dms_rift *rift)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(!rift);

	/* A KEYLESS tracker was never given a rift key. */
	if (_rift_key_error(tracker->hdr.local_rift_key) == HFI2_DMS_RIFT_ERR_KEYLESS)
		return;

	_rift_release(rift, tracker->hdr.local_rift_key);
}

/* Eager WAW release. Called after the parent's START has left via PIO. */
static void _dms_write_signal_pio_release(struct hfi2_dms *dms,
					  struct hfi2_dms_tx_tracker *tx_tracker)
{
	union hfi2_dms_tracker *const parent = (union hfi2_dms_tracker *)tx_tracker;
	union hfi2_dms_tracker *child;
	int ret;

	/* A SEND is fully fenced: it releases its child only at completion. */
	if (_tx_tracker_is_send(tx_tracker))
		return;

	/* An eager WAW child that binds after this is released at bind. */
	parent->hdr.chain_pio_released = true;

	if (parent->hdr.chain_signalled || parent->hdr.child_handle.value == 0)
		return;

	child = _handle_to_tracker(parent->hdr.child_handle);
	if (!child ||
	    child->hdr.op != HFI2_DMS_XFER_OP_WRITE ||
	    child->hdr.parent_handle.value != _tracker_to_handle(parent).value ||
	    child->hdr.chain_park_at !=
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
		return;

	/* Claim the release exactly once. */
	parent->hdr.chain_signalled = true;
	child->hdr.chain_child_released = true;

	/* Not parked yet: the child self-starts at its gate. */
	if (child->hdr.health_state !=
	    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
		return;

	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	_tracker_health_state_set(dms, child,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	/* Queued, not sent: the child signals its own child when it leaves. */
	ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
					       HFI2_DMS_MSG_TYPE_WRITE_START,
					       true);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
		return;
	}
	dms->counters.chain_released_write++;
	dms->counters.chain_released_write_pio_parked++;
}

static void _tracker_signal(struct hfi2_dms *dms, union hfi2_dms_tracker *parent, int status)
{
	struct hfi2_dms_transfer_handle const parent_h = _tracker_to_handle(parent);
	struct hfi2_dms_transfer_handle const child_h = parent->hdr.child_handle;
	union hfi2_dms_tracker *child;

	/* Latch: refuse late binds; we will not signal again. */
	parent->hdr.chain_signalled = true;
	if (child_h.value == 0)
		return;

	child = _handle_to_tracker(child_h);
	if (!child) {
		/* Child retired (cancelled/recycled) before parent completed. */
		dms->counters.chain_null_handle++;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (child->hdr.parent_handle.value != parent_h.value) {
		/* Link no longer reciprocal: drop it. */
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (status && child->hdr.park_on_parent_error) {
		child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		dms->counters.chain_parked_on_parent_error++;
		return;
	}

	child->hdr.chain_child_released = true;

	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START ||
	    child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY ||
	    child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		_tracker_health_state_set(dms, child,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);
		ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
						       HFI2_DMS_MSG_TYPE_WRITE_START,
						       false);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_write++;
		dms->counters.chain_released_write_ack++;
		if (child->hdr.chain_park_at ==
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
			dms->counters.chain_released_write_pio_ack++;
		return;
	}

	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		_tracker_health_state_set(dms, child,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START);
		ret = hfi2_dms_impl_inject_read_start(dms, &child->rx, NULL, 0,
						      HFI2_DMS_MSG_TYPE_READ_START);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_read++;
		return;
	}

	/* Completion-time release: sole path for DATA_START_LARGE, fallback for a
	 * DATA_START child not already released by the narrow-to-one fast path.
	 */
	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		ret = _chain_resume_read_at_data_start(dms, &child->rx);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_read_at_data_start_large++;
		return;
	}

	if (child->hdr.health_state ==
		HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) {
		bool const raw = parent->hdr.op == HFI2_DMS_XFER_OP_WRITE;
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		ret = _chain_resume_read_at_data_start(dms, &child->rx);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		if (raw)
			dms->counters.chain_released_read_at_data_start_raw++;
		else
			dms->counters.chain_released_read_at_data_start++;
		return;
	}
}

static void _dms_rx_tracker_complete_finish(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker,
					    int status);

static void _dms_rx_p2p_flush_done(void *cookie, int status)
{
	struct hfi2_dms_rx_tracker *rx_tracker = cookie;
	struct hfi2_dms *dms = rx_tracker->dms;

	dms->p2p_flush_inflight--;
	WARN_ON_ONCE(status && status != -ESHUTDOWN);
	_dms_rx_tracker_complete_finish(dms, rx_tracker,
					status == -ESHUTDOWN ?
					-ECANCELED : status);
}

static bool _dms_rx_p2p_flush_start(struct hfi2_dms *dms,
				    struct hfi2_dms_rx_tracker *rx_tracker)
{
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	struct hfi2_dms_run run;
	struct sdma_desc descs[2];
	u64 last_byte;
	u8 engine = dms_reserved_engine_idx(dms);
	u8 port_idx = rx_tracker->hdr.port_idx;
	int ret;

	if (!pp->p2p_flush || !rx_tracker->sbuf_cursor)
		return false;
	if (WARN_ON_ONCE(!dms->num_engines ||
			 !dms->p2p_flush_sop_desc[port_idx].qw[0]))
		return false;

	last_byte = rx_tracker->rbuf_start_offset + rx_tracker->total_payload - 1;
	if (WARN_ON_ONCE(pp->next_src_run(pp, last_byte, 1, &run) ||
			 !run.run_bytes))
		return false;

	descs[0] = dms->p2p_flush_sop_desc[port_idx];
	descs[1] = (struct sdma_desc){0};
	_sdma_qw_set_byte_count(&descs[1].qw[0], sizeof(u64));
	_sdma_qw_set_phy_addr(&descs[1].qw[0],
			      run.dma_pages[0] + (run.page_offset & ~0x7ull));
	descs[1].qw[1] |= HFI2_DMS_SDMA_DESC_TYPE_EOP |
		SDMA_DESC1_HEAD_TO_HOST_FLAG;
	if (dms->chip_type != CHIP_JKR)
		cyr_sdma_qw_set_send_ctxt_extension(&descs[1].qw[0],
						    dms->port_sctxts[port_idx]->hw_context);

	rx_tracker->dms = dms;
	ret = hfi2_dms_sdma_desc_place(dms, engine, descs, ARRAY_SIZE(descs),
				       _dms_rx_p2p_flush_done, rx_tracker);
	if (!ret) {
		hfi2_dms_sdma_doorbell_all(dms);
	} else {
		ret = hfi2_dms_sdma_desc_submit(dms, engine, port_idx, descs,
						ARRAY_SIZE(descs),
						_dms_rx_p2p_flush_done,
						rx_tracker);
		if (WARN_ON_ONCE(ret))
			return false;
	}

	dms->p2p_flush_inflight++;
	return true;
}

void hfi2_dms_rx_tracker_handle_completion(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int status, u32 do_ack)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->payload_remaining != 0);

	enum hfi2_dms_rx_tracker_op const op = rx_tracker->op;

	if (do_ack) {
		union hfi2_dms_proto_cmd_ack cmd;
		int ret;

		DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

		if (op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
			cmd = hfi2_dms_proto_cmd_ack_make(dms, rx_tracker->hdr.port_idx, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, rx_tracker->read.flags, rx_tracker->read.imm_data);
		} else { /* externally-resolved or RDMA-WRITE target: ACK carries no imm */
			cmd = hfi2_dms_proto_cmd_ack_make(dms, rx_tracker->hdr.port_idx, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, 0, 0);
		}

		ret = _inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
				      HFI2_DMS_TRANSFER_HANDLE_NONE, false);
		if (ret < 0)
			dd_dev_err(dms->dd, "Failed to send or enqueue ACK packet\n");
	}

#if HFI2_DMS_COUNTERS_ENABLE
	rx_tracker->hdr.perf.lifetime[1] = ktime_get();
	_dms_aggregate_perf_counters(dms, (union hfi2_dms_tracker *)rx_tracker);
#endif
	_tracker_rift_release(dms, (union hfi2_dms_tracker *)rx_tracker, &dms->rift);

	if (!status && _dms_rx_p2p_flush_start(dms, rx_tracker))
		return;
	_dms_rx_tracker_complete_finish(dms, rx_tracker, status);
}

static void _dms_rx_tracker_complete_finish(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker,
					    int status)
{
	enum hfi2_dms_rx_tracker_op const op = rx_tracker->op;

	/* Parent signals to child upon rx completion. */
	_tracker_signal(dms, (union hfi2_dms_tracker *)rx_tracker, status);

	if (op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, status);
	} else if (op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST) {
		dms->ext_dest.complete(dms,
			rx_tracker->write.ext_cmpl_ctx, status);
	} else { // HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access,
			(union hfi2_dms_tracker *)rx_tracker,
			rx_tracker->write.metadata.flags,
			rx_tracker->write.parameters.imm_data,
			rx_tracker->write.parameters.order_key,
			status);
		rx_tracker->write.access = NULL;
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);

	/*
	 * Hand the freed rift key on once this tracker is retired, but defer
	 * the poll: this completion can run nested inside a rift-poll drive.
	 */
	_dms_rift_poll_request(dms);
}

static void _dms_rx_issue_data_request_burst(struct hfi2_dms *dms,
					     struct hfi2_dms_rx_tracker *rx_tracker,
					     bool deferred)
{
	u32 const free_count = _tidset_free_count(dms);
	u32 tidset;
	int ret;

	DMS_BUG_ON(rx_tracker->tidsets_in_use != 0);

	if ((!_rift_keyring_empty(&dms->tidset_waiters)) || (free_count == 0)) {
		if (deferred)
			dms->counters.chain_resume_deferred_waiter++;
		_tidset_waiter_enqueue(dms, rx_tracker);
		return;
	}

	_tidset_idx_peek(dms, &tidset);
	_tidset_idx_reserve(dms, tidset);
	ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
	if (unlikely(ret != 0)) {
		_tidset_idx_release(dms, tidset);
		_tidset_waiter_enqueue(dms, rx_tracker);
		return;
	}
	DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
	_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);

	for (u32 i = 1; i < HFI2_DMS_TRACKER_TIDSET_MAX &&
	     rx_tracker->sbuf_cursor < rx_tracker->total_payload &&
	     free_count > i; i++) {
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
	}

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA);

	_chain_signal_last_engine(dms, rx_tracker);
}

/*
 * Allocate additional tidsets for the unrequested remainder of a transfer whose
 * tracker already holds in-use tidsets, issuing one DATA_REQUEST per newly
 * reserved tidset. The loop seeds from the current in-use count so the
 * per-tracker maximum caps total (not additional) tidsets, and bounds
 * reservations to the free pool. On pool exhaustion the tracker is left for the
 * per-tidset re-request path rather than enqueued as a waiter, since it still
 * has live tidsets in flight.
 */
static void _dms_rx_speculative_topup_burst(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker)
{
	u32 const start = rx_tracker->tidsets_in_use;
	u32 const free_count = _tidset_free_count(dms);
	u32 tidset;
	int ret;

	if (!_rift_keyring_empty(&dms->tidset_waiters) || free_count == 0)
		return;

	for (u32 i = start;
	     i < HFI2_DMS_TRACKER_TIDSET_MAX &&
	     (rx_tracker->sbuf_cursor < rx_tracker->total_payload) &&
	     ((i - start) < free_count);
	     i++) {
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
	}
}

static int _chain_resume_read_at_data_start(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker)
{
	u32 const tid_nbytes = rx_tracker->total_payload -
			       rx_tracker->sbuf_cursor;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	if (unlikely(tid_nbytes == 0))
		return 0;

	_dms_rx_issue_data_request_burst(dms, rx_tracker, true);
	return 0;
}

static void hfi2_dms_handle_data_start(struct hfi2_dms *dms,
				       union hfi2_dms_16b_header *hdr,
				       bool eager, void *ebuf, u32 const eager_nbytes)
{
	struct _hdrq_entry *e = (struct _hdrq_entry *)hdr;
	struct hfi2_dms_data_start_parameters const * const parameters = &e->data_start;
	hfi2_dms_rift_key_t const rx_rift_key = parameters->rx_rift_key;
	hfi2_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;
	void *hbuf = eager ? (void *)&parameters->eager_payload : NULL;

	struct hfi2_dms_rx_tracker *rx_tracker;
	int err = 0;

	if (unlikely(_rift_key_error(rx_rift_key) || !_rift_key_side_rx(rx_rift_key) ||
		     _rift_key_error(tx_rift_key) || !_rift_key_side_tx(tx_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop DATA_START with malformed rift keys rx=0x%04hx tx=0x%04hx\n",
			   rx_rift_key.value, tx_rift_key.value);
		return;
	}

	rx_tracker = (struct hfi2_dms_rx_tracker *) _rift_lookup(&dms->rift, rx_rift_key);
	if (!rx_tracker) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, rx_rift_key.value, _rift_key_generation(rx_rift_key), _rift_key_index(rx_rift_key));
		return;
	}
	/*
	 * A speculative READ's responder answers DATA_START when it could not
	 * serve the requests the READ_START carried: promote and re-request.
	 */
	if (unlikely(_rx_tracker_spec_unlatched(rx_tracker))) {
		_spec_read_join(dms, rx_tracker, tx_rift_key, true);
		return;
	}
	/*
	 * Duplicate DATA_START guard: the remote side may re-send DATA_START
	 * via the health protocol if it didn't receive a timely DATA_REQUEST.
	 * If remote_rift_key is already set, this rx_tracker has already
	 * processed a DATA_START - ignore the duplicate.
	 */
	if (_rift_key_error(rx_tracker->hdr.remote_rift_key) != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {
		dms->counters.health_duplicate_data_start++;
		dd_dev_dbg(dms->dd,
			"(%d) Ignoring duplicate DATA_START for rx_tracker (l:%05u r:%05u)\n",
			__LINE__,
			rx_tracker->hdr.local_rift_key.value,
			rx_tracker->hdr.remote_rift_key.value);
		return;
	}

	rx_tracker->hdr.remote_rift_key = tx_rift_key;

	if (rx_tracker->payload_remaining == 0) {
		/* Complete using fence only. */

		dms->counters.eager_rx++;
		goto completed_success;
	}

	if (hbuf) {
		/*
		 * Eager: the packet carries the first eager_nbytes of the
		 * payload, or all of it. Land that prefix by CPU and request
		 * the rest.
		 */
		u32 const prefix = min_t(u32, rx_tracker->total_payload,
					 eager_nbytes);

		err = _eager_rx_copy_prefix(rx_tracker,
			HFI2_DMS_MSG_TYPE_DATA_START_EAGER,
			hbuf, ebuf, prefix);
		if (unlikely(err != 0))
			goto completed_error;

		dms->counters.eager_rx++;
		rx_tracker->hdr.byte_odometer += prefix;
		rx_tracker->payload_remaining -= prefix;
		if (rx_tracker->payload_remaining == 0)
			goto completed_success;

		rx_tracker->sbuf_cursor = prefix;
	} else if (_tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
				 HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) ||
		   _tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
				 HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE)) {
		/* Parked at whichever DATA_START variant _tracker_bind chose. */
		dms->counters.chain_parked_read_at_data_start++;
		return; /* DATA_REQUEST burst deferred to resume */
	}

	/*
	 * The tidsets request the payload not yet delivered; any sub-quadword
	 * edges, the start or end of the buffer included, land through the
	 * tidset bounce page.
	 */
	_dms_rx_issue_data_request_burst(dms, rx_tracker, false);
	return;

completed_success:
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, true);
	return;

completed_error:
	rx_tracker->payload_remaining = 0;
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, err, true);
	return;
}

static void _hfi2_dms_handle_data_common(struct hfi2_dms *dms,
					 union hfi2_dms_16b_header *hdr,
					 bool speculative)
{
	u64 start, end;
	struct hfi2_dms_read_request_state *read_request;
	struct hfi2_dms_rx_tracker *rx_tracker;
	u16 tid;
	u16 tid_set;
	u32 payload_qws;

	dms_trace(dms_handle_data, dms, hdr);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	start = dms_rdtsc();

	tid = (hdr->kdeth[0] >> 16) & (BIT(10) - 1);
	tid_set = (tid / HFI2_DMS_TID_SET_SIZE);
	payload_qws = hfi2_dms_16b_data_payload_qws_get(hdr);

	read_request = &dms->read_requests[tid_set];
	union hfi2_dms_proto_pkt_data *data_pkt = (union hfi2_dms_proto_pkt_data *)hdr;
	u16 const pkt_generation = data_pkt->info.generation;

	if (unlikely((read_request->state != HFI2_DMS_TIDSET_STATE_ENABLED) ||
		     (pkt_generation != read_request->generation)))  {
		/*
		 * A generation mismatch on a tidset that is still ENABLED and has
		 * already accepted legit data (remaining_qws != total_requested_qws)
		 * means a hardware DMA placed a foreign payload into a live receive
		 * buffer before we dropped the header here. The u16 epoch and FIFO
		 * recycling make this unreachable within the fabric packet lifetime;
		 * if it fires it is silent data corruption and the signal to widen
		 * the epoch or add a stronger transfer-identity token.
		 */
		if (read_request->state == HFI2_DMS_TIDSET_STATE_ENABLED &&
		    read_request->remaining_qws != read_request->total_requested_qws) {
			dms->counters.data_generation_mismatch_clobber++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS: stale DATA clobber tid_set=%u pkt_gen=%u cur_gen=%u\n",
				tid_set, pkt_generation, read_request->generation);
		}
		/* Ignore this invalid DATA packet */
		if (read_request->state == HFI2_DMS_TIDSET_STATE_DRAINING) {
			read_request->stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);
		} else {
			read_request->disable_ts = dms->now;
		}
		return;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	if (read_request->remaining_qws == read_request->total_requested_qws) {
		dms->read_requests[tid_set].perf.first_data = ktime_get();
	}
#endif

	rx_tracker = read_request->rx_tracker;
	DMS_BUG_ON(!rx_tracker);

	/*
	 * Promotion: the first DATA_SPECULATIVE names the responder of a
	 * speculative READ, turning its speculative tidsets into ordinary ones.
	 * The packet then lands as ordinary DATA below. DATA never takes this
	 * branch.
	 */
	if (speculative && _rx_tracker_spec_unlatched(rx_tracker))
		_spec_read_join(dms, rx_tracker, data_pkt->info.tx_rift_key, false);

	/*
	 * New generation-valid DATA landed (the invalid/duplicate/old-gen path
	 * returned above). Advance the lifetime work odometer so this tracker's
	 * progress hash differs on genuine forward progress only.
	 */
	rx_tracker->hdr.byte_odometer += (u64)payload_qws << 3;
	rx_tracker->hdr.status_req_count = 0;
	rx_tracker->hdr.stale_time = ktime_add_ms(dms->now, HFI2_DMS_STALE_BACKOFF_BASE_MS);
	read_request->stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);

	/* Avoid unsigned underflow that can stall tidset completion. */
	if (unlikely(read_request->remaining_qws < payload_qws)) {
		dms->counters.health_remaining_qws_underflow++;
		dd_dev_dbg_ratelimited(dms->dd,
				       "dms: remaining_qws (%llu) < payload_qws (%u) on tid_set %u gen %u, cancelling rx_tracker\n",
				       read_request->remaining_qws, payload_qws,
				       tid_set, pkt_generation);
		hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -EIO);
		return;
	}
	read_request->remaining_qws -= payload_qws;

	if (read_request->remaining_qws > 0) {
		// more data is expected for this tidset
		return;
	}

	// all data for this tidset has been received
	if (unlikely(read_request->has_bounce)) {
		/*
		 * The request's sub-quadword edges landed in the bounce page;
		 * they reach the destination only once copied out, so debit the
		 * request's destination bytes after that succeeds. A failed
		 * copy-out leaves edge bytes missing: cancel rather than report
		 * success.
		 */
		if (unlikely(_tidset_bounce_scatter(dms, tid_set, rx_tracker))) {
			dms->counters.health_bounce_scatter_fail++;
			hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -EIO);
			return;
		}
		rx_tracker->payload_remaining -=
			dms->read_request_chunks[tid_set].cycle_real_bytes;
	} else {
		/* No edges: every destination byte was placed by TID. */
		rx_tracker->payload_remaining -=
			read_request->total_requested_qws << 3;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	read_request->perf.end = ktime_get();
	if (_ring_free(&dms->counters.tidset.ring) > 0) {
		u32 const idx = _ring_produce(&dms->counters.tidset.ring);

		dms->counters.tidset.arr[idx].enable = ktime_sub(read_request->perf.tidset_enabled, read_request->perf.begin);
		dms->counters.tidset.arr[idx].rtt = ktime_sub(read_request->perf.first_data, read_request->perf.tidset_enabled);
		dms->counters.tidset.arr[idx].total = ktime_sub(read_request->perf.end, read_request->perf.begin);
		dms->counters.tidset.arr[idx].data = ktime_sub(read_request->perf.end, read_request->perf.first_data);
		dms->counters.tidset.arr[idx].bytes = read_request->total_requested_qws << 3;
		dms->counters.tidset.arr[idx].local = rx_tracker->hdr.local_rift_key;
		dms->counters.tidset.arr[idx].remote = rx_tracker->hdr.remote_rift_key;
		dms->counters.tidset.arr[idx].order_key = rx_tracker->hdr.order_key;
		dms->counters.tidset.arr[idx].tbytes = rx_tracker->total_payload;
	}
#endif

	if (rx_tracker->sbuf_cursor < rx_tracker->total_payload) {
		int ret;

		/* Re-arm for the next chunk (may land on a new engine). Stays in the
		 * list on success; removed on failure.
		 */
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tid_set);
		if (ret == 0) {
			_chain_signal_last_engine(dms, rx_tracker);
		} else {
			_dms_rx_tracker_tidset_inflight_clear(rx_tracker, tid_set);

			if (rx_tracker->tidsets_in_use == 0) {
				/* No other tidset will complete the transfer; Add to front of
				 * tidset waiter ring (priority over new waiters)
				 */
				hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
				_rift_keyring_add_front(&dms->tidset_waiters, key);

				_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
								HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION);
			}

			_tidset_free_then_poll_waiters(dms, tid_set);
		}
		return;
	}

	_dms_rx_tracker_tidset_inflight_clear(rx_tracker, read_request->tid_set);
	_tidset_free_then_poll_waiters(dms, read_request->tid_set);

	_chain_signal_last_engine(dms, rx_tracker);

	if (rx_tracker->payload_remaining == 0)
		hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);

	end = dms_rdtsc();
	dms->counters.handle_data += end - start;
}

static void hfi2_dms_handle_data(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	_hfi2_dms_handle_data_common(dms, hdr, false);
}

static void hfi2_dms_handle_data_speculative(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	_hfi2_dms_handle_data_common(dms, hdr, true);
}

static inline enum hfi2_dms_msg_type
hfi2_dms_impl_message_type_get(union hfi2_dms_16b_header *hdr)
{
	enum hfi2_dms_msg_type ret;

	ret = (enum hfi2_dms_msg_type)((hdr->bth[0] & 0x00FF0000) >>
				       16); // Extract the message type from BTH
	return ret;
}

/* CYR and JKR RHF bit layouts are identical — keep raw constants for hot path */
static bool _rhf_is_valid_16b(u64 rhf)
{
	u64 const mask = ((u64)RHF_JKR_RHE_VALID) |
			 ((u64)RHF_JKR_L2_TYPE_MASK << RHF_JKR_L2_TYPE_SHIFT);
	u64 const check = (u64)HFI2_L2_TYPE_16B << RHF_JKR_L2_TYPE_SHIFT;

	return (rhf & mask) == check;
}

static void _log_rhe_reason(struct hfi2_dms *dms, struct hfi2_ctxtdata *rcd,
			    u64 rhf, u32 rhqoff, u32 rsize)
{
	// We set hardware to drop 9B packets to our rcd
	DMS_WARN_ON(_rhf_l2_type(rhf) != HFI2_L2_TYPE_16B);

	if (_rhf_rhe_valid(rhf)) {
		u64 err_flags = ((u64 *)(rcd->rheq))[rhqoff / rsize];

		if (err_flags & RHF_ICRC_ERR)
			dd_dev_dbg(
				dms->dd,
				"DMS data packet dropped due to ICRC error\n");
		else
			dd_dev_dbg(
				dms->dd,
				"DMS data packet dropped due to unhandled error (0x%016llx)\n",
				err_flags);
	}
}

/**
 * _get_rhf_addr - Get the RHF address for a given queue offset
 * @rcd: receive context
 * @rhqoff: queue offset in words
 */
static inline __le32 *_get_rhf_addr(struct hfi2_ctxtdata *rcd, u32 rhqoff)
{
	return (__le32 *)rcd->rcvhdrq + rhqoff + rcd->rhf_offset;
}

/**
 * _get_16b_hdr - Get the 16B header pointer from the RHF address
 * @rcd: receive context
 * @rhf_addr: pointer to the RHF in the header queue
 * @rhf: the RHF value (already read)
 */
static inline union hfi2_dms_16b_header *_get_16b_hdr(struct hfi2_ctxtdata *rcd,
						      __le32 *rhf_addr, u64 rhf)
{
	return (union hfi2_dms_16b_header *)(rhf_addr - rcd->rhf_offset +
					     rhf_hdrq_offset(rhf));
}

/* LRH16(16) + BTH(12) + KDETH(8); hbuf (inline payload) starts here. */
#define HFI2_DMS_ULP_HDR_BYTES 36u

/*
 * On the wire the 36-byte header is qword-rounded: hfi2_dms_ulp_build_pio_header()
 * counts DIV_ROUND_UP(36, 8) = 5 qwords = 40 bytes for the header region in
 * pkt_len_qws, leaving a 4-byte qword-rounding pad between the header and the
 * payload.  rhf_pkt_len() reflects that rounded length, so the receive-side
 * payload split MUST strip the rounded header (40), not the raw 36, or the pad
 * bytes leak into the payload handed to the ULP.
 */
#define HFI2_DMS_ULP_HDR_WIRE_BYTES round_up(HFI2_DMS_ULP_HDR_BYTES, sizeof(u64))

/* Mandatory 16B tail flit (1 qword) every DMS 16B packet carries after payload. */
#define HFI2_DMS_ULP_TAIL_BYTES 8u

/*
 * Split a received ULP packet into the {hbuf, ebuf} iovec the handler sees.
 * The inline prefix (hbuf) is the portion that fit in the HDRQ entry after the
 * 36-byte header, capped by the entry size (JKR 128 / CYR 256, minus the 2-DW
 * RHF); the remainder spilled into the eager buffer (ebuf).
 *
 * rhf_pkt_len() counts the whole on-wire packet after the header: the ULP
 * payload PLUS the mandatory 8-byte 16B tail flit that the egress path always
 * appends (and any qword-rounding pad).  Strip that trailer here so the payload
 * lengths the handler sees match what the sender passed as @payload_bytes and
 * no trailer bytes are exposed as payload.
 */
static struct hfi2_dms_ulp_rx _dms_build_ulp_rx(struct hfi2_ctxtdata *rcd,
						u64 rhf,
						union hfi2_dms_16b_header *hdr,
						void *ebuf)
{
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const rhf_off = rhf_hdrq_offset(rhf);
	/*
	 * prefix_cap is the byte span of the HDRQ entry after the RHF (2 DWs).
	 * Guard the subtraction: a malformed rhf_hdrq_offset (>= rsize - 2) would
	 * underflow u32 to a huge value and push payload[0] past the entry.  The
	 * poll loop already validated the RHF, so this is defence-in-depth.
	 */
	u32 const prefix_cap = (rsize > rhf_off + 2) ?
			       (rsize - rhf_off - 2) << 2 : 0;
	u32 const inline_cap = prefix_cap > HFI2_DMS_ULP_HDR_WIRE_BYTES ?
			       prefix_cap - HFI2_DMS_ULP_HDR_WIRE_BYTES : 0;
	u32 const pkt_len = rhf_pkt_len(rhf);
	/*
	 * Strip the WIRE (qword-rounded, 40-byte) header + the 8-byte tail flit.
	 * The header lands at command-buffer offset HFI2_DMS_ULP_HDR_BYTES(36) but
	 * pkt_len counts the rounded HFI2_DMS_ULP_HDR_WIRE_BYTES(40); stripping 36
	 * here would expose the 4-byte qword pad as payload.
	 */
	u32 const hdr_plus_tail = HFI2_DMS_ULP_HDR_WIRE_BYTES +
				  HFI2_DMS_ULP_TAIL_BYTES;
	u32 const total_pay = pkt_len > hdr_plus_tail ?
			      pkt_len - hdr_plus_tail : 0;
	u32 const hbuf_len = min(total_pay, inline_cap);
	u32 const ebuf_len = total_pay - hbuf_len;

	return (struct hfi2_dms_ulp_rx){
		.pkt_hdr = hdr,
		.payload[0] = {
			.base = hbuf_len ?
				(const u8 *)hdr + HFI2_DMS_ULP_HDR_WIRE_BYTES :
				NULL,
			.len = hbuf_len,
		},
		.payload[1] = {
			.base = ebuf_len ? ebuf : NULL,
			.len = ebuf_len,
		},
		.rcv_port = _rhf_rcv_port(rhf),
	};
}

/*
 * The native builder's HFI2_DMS_ULP_HDR_WIRE_BYTES/HFI2_DMS_ULP_TAIL_BYTES
 * offsets cannot parse EAL ingress + Ethernet/IP/UDP.  The RSM bypass split
 * determines the HDRQ-inline prefix, with the remainder in the eager buffer.
 * The header starts at the RHF-provided offset within the HDRQ entry.
 */
static inline u32 _eth_bypass_header_budget(struct hfi2_ctxtdata *rcd, u64 rhf)
{
	u32 const hdrq_cap = (get_hdrqentsize(rcd) > rhf_hdrq_offset(rhf) + 2) ?
		(get_hdrqentsize(rcd) - rhf_hdrq_offset(rhf) - 2) << 2 : 0;

	return min_t(u32, hdrq_cap,
		hfi2_dms_eth_bypass_hdr_dws(rcd->dd) * sizeof(u32));
}

static bool _dms_build_eth_ulp_rx(struct hfi2_ctxtdata *rcd, u64 rhf,
				  const struct eal_ingress_header *eal_hdr,
				  void *ebuf, struct hfi2_dms_ulp_rx *rx)
{
	u32 const pkt_len = rhf_pkt_len(rhf);
	u32 const hdr_bytes = sizeof(*eal_hdr);
	u32 const header_budget = _eth_bypass_header_budget(rcd, rhf);
	u32 const pad = EAL_INGRESS_GET_E(eal_hdr);
	u32 inline_bytes;
	u32 eth_bytes;
	u32 ebuf_len;
	const u8 *inline_base;
	const void *timestamp = NULL;

	if (pkt_len < hdr_bytes || header_budget < hdr_bytes)
		return false;

	inline_bytes = min(pkt_len - hdr_bytes, header_budget - hdr_bytes);
	eth_bytes = pkt_len - hdr_bytes;
	inline_base = (const u8 *)eal_hdr + hdr_bytes;
	if (EAL_INGRESS_GET_TS_PRESENT(eal_hdr)) {
		if (eth_bytes < CNE_RX_TS_SIZE || inline_bytes < CNE_RX_TS_SIZE)
			return false;
		timestamp = inline_base;
		inline_base += CNE_RX_TS_SIZE;
		inline_bytes -= CNE_RX_TS_SIZE;
		eth_bytes -= CNE_RX_TS_SIZE;
	}
	/* RHF length includes EAL header, optional timestamp and qword pad. */
	if (eth_bytes < pad)
		return false;
	eth_bytes -= pad;
	inline_bytes = min(inline_bytes, eth_bytes);
	ebuf_len = eth_bytes - inline_bytes;
	/* The eager offset is relative to the start of this RcvArray slot. */
	if (ebuf_len && (!ebuf ||
			 (u64)rhf_egr_buf_offset(rhf) * RCV_BUF_BLOCK_SIZE + ebuf_len >
			 rcd->egrbufs.rcvtid_size))
		return false;

	*rx = (struct hfi2_dms_ulp_rx){
		.pkt_hdr = eal_hdr,
		.payload[0] = {
			.base = inline_bytes ? inline_base : NULL,
			.len = inline_bytes,
		},
		.payload[1] = {
			.base = ebuf_len ? ebuf : NULL,
			.len = ebuf_len,
		},
		.ingress_timestamp = timestamp,
		.rcv_port = _rhf_rcv_port(rhf),
		.is_ethernet = true,
	};
	return true;
}

/*
 * Route a classified ULP packet (ulp_id != 0) toward its registered handler.
 * A slot whose handle_rx is NULL (no ULP registered for that ulp_id, or a ULP
 * that has unregistered) accounts the packet exactly like the poll loops'
 * existing "unknown message type" default arm and returns.  ULPs populate
 * dms->ulp[] via hfi2_dms_ulp_register()/unregister() (below).
 *
 * Single-threaded: runs on the bulksvc event thread; reads dms->ulp[] without
 * locking by design (see struct hfi2_dms).
 */
static void hfi2_dms_ulp_dispatch_rx(struct hfi2_dms *dms, u8 ulp_id,
				     u8 subtype,
				     const struct hfi2_dms_ulp_rx *rx)
{
	const struct hfi2_dms_ulp_ops *ops;

	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		goto drop;

	ops = &dms->ulp[ulp_id];
	if (ops->handle_rx &&
	    ops->handle_rx(dms, subtype, rx, ops->cookie) == 0)
		return;

drop:
	dd_dev_dbg_ratelimited(dms->dd,
			       "Dropping ULP packet (no handler): ulp_id=%u subtype=%u\n",
			       ulp_id, subtype);
}

int hfi2_dms_ulp_register(struct hfi2_dms *dms, struct hfi2_dms_ulp_ops ops)
{
	u8 ulp_id;

	/*
	 * Validate the full ops vtable here so the hot dispatch path never has
	 * to: a registered slot is guaranteed to have a non-NULL handle_rx.
	 */
	if (!dms || !ops.handle_rx)
		return -EINVAL;

	ulp_id = ops.ulp_id;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;

	if (dms->ulp[ulp_id].handle_rx)
		return -EBUSY;

	dms->ulp[ulp_id] = ops;
	return 0;
}

void hfi2_dms_ulp_unregister(struct hfi2_dms *dms, u8 ulp_id)
{
	if (!dms || ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return;

	dms->ulp[ulp_id] = (struct hfi2_dms_ulp_ops){0};
}

/*
 * Build the PIO-command header (PBC + 16B-compressed LRH + BTH + KDETH) for a
 * ULP PIO packet into @hdr_buf, so a ULP peer can hand iov[0]=hdr_buf,
 * iov[1]=payload to hfi2_dms_ulp_egress_pio() without reaching into DMS
 * internals.  The command frame uses the 8-byte compressed lrh16bc, so the
 * header after the PBC is lrh16bc(8) + bth(12) + kdeth(8) = 28 bytes, zero
 * padded by 4 so the payload follows at command-buffer offset 40.  That same
 * payload lands at WIRE offset 40 once the 16B LRH expands, matching the
 * receive-side HFI2_DMS_ULP_HDR_WIRE_BYTES.  The 8-bit BTH message byte is
 * encoded as
 * (ulp_id << HFI2_DMS_MSGBYTE_ULP_SHIFT) | (subtype & HFI2_DMS_MSGBYTE_SUB_MASK),
 * matching hfi2_dms_16b_ulp_decode().  SLID is stamped by the send context's
 * SendCtxtCheckSlid at injection time, so it is not set here.  Returns the
 * command-header length in bytes (40), or a negative errno.
 */
int hfi2_dms_ulp_build_pio_header(struct hfi2_dms *dms,
				  enum hfi2_dms_fabric_port_idx port_idx,
				  u32 dlid, u8 ulp_id, u8 subtype,
				  u32 payload_bytes, void *hdr_buf,
				  u32 hdr_buf_len)
{
	/*
	 * Command-buffer header: PBC(8) + lrh16bc(8) + bth(12) + kdeth(8) = 36,
	 * zero-padded to 40 so the payload starts on a qword.  The compressed
	 * lrh16bc is 8 bytes here; the WIRE header it expands to is
	 * 16 + bth(12) + kdeth(8) = 36, padded the same way, so the payload
	 * lands at wire offset 40 -- HFI2_DMS_ULP_HDR_WIRE_BYTES, where the
	 * receive split expects it.
	 */
	u32 const hdr_bytes = round_up(sizeof(u64) /* PBC */ + 8 /* lrh16bc */ +
				       12 /* bth */ + 8 /* kdeth */,
				       sizeof(u64));
	struct send_context *sc;
	union _pkt_cmd *cmd;
	u32 pkt_len_qws;
	u8 msgbyte;

	if (!dms || !hdr_buf)
		return -EINVAL;
	/* The batch stores u64 PBC/LRH/BTH/KDETH fields; require alignment. */
	if (!IS_ALIGNED((uintptr_t)hdr_buf, sizeof(u64)))
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS || !dms->port_available[port_idx])
		return -EINVAL;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;
	if (subtype > HFI2_DMS_MSGBYTE_SUB_MASK)
		return -EINVAL;
	if (dlid == 0)
		return -EINVAL;
	if (payload_bytes & (sizeof(u64) - 1))
		return -EINVAL;
	if (hdr_buf_len < hdr_bytes)
		return -EMSGSIZE;

	sc = dms->port_sctxts[port_idx];
	if (!sc)
		return -ENXIO;

	/*
	 * On-wire qword length carried in the LRH/PBC excludes the PBC itself
	 * but includes the 36-byte header and a 1-qword tail flit.  The 36-byte
	 * header rounds up to 5 qwords on the wire.
	 */
	pkt_len_qws = DIV_ROUND_UP(36, sizeof(u64)) +
		      (payload_bytes / sizeof(u64)) + 1;

	cmd = hdr_buf;
	memset(cmd, 0, hdr_bytes);

	cmd->pbc = hfi2_dms_impl_pbc_template_create_16Bc(port_idx,
							  pkt_len_qws << 1,
							  sc->hw_context);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);

	msgbyte = (ulp_id << HFI2_DMS_MSGBYTE_ULP_SHIFT) |
		  (subtype & HFI2_DMS_MSGBYTE_SUB_MASK);
	cmd->bth[0] = HFI2_DMS_BTH_OPCODE | ((u32)msgbyte << 16);
	cmd->bth[1] = (u32)RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; /* KVER */
	cmd->kdeth[1] = HFI2_DMS_CTRL_JKEY;

	return hdr_bytes;
}

int hfi2_dms_ulp_egress_pio(struct hfi2_dms *dms,
			    enum hfi2_dms_fabric_port_idx port_idx,
			    const struct hfi2_dms_ulp_iov *iov, u32 niov)
{
	struct hfi2_dms_ulp_iov spans[HFI2_DMS_ULP_PIO_MAX_IOV];
	const u8 *hdr;
	u32 i;
	int ret;

	if (!dms || !iov || niov == 0 || niov > HFI2_DMS_ULP_PIO_MAX_IOV)
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS)
		return -EINVAL;

	/*
	 * iov[0] MUST start with the PBC qword from
	 * hfi2_dms_ulp_build_pio_header(): enforce it up front so a {NULL,0}
	 * or short first element can never let payload bytes be misread as
	 * the PBC and emit a corrupted packet.
	 */
	if (!iov[0].base || iov[0].len < sizeof(u64))
		return -EINVAL;

	/*
	 * Hand the PBC to the gather sender separately and the rest of the
	 * packet as packed spans; the sender appends the 16B tail flit.
	 */
	hdr = iov[0].base;
	spans[0] = (struct hfi2_dms_ulp_iov){ .base = hdr + sizeof(u64),
					      .len = iov[0].len - sizeof(u64) };
	for (i = 1; i < niov; i++)
		spans[i] = iov[i];

	if (_pio_waitlist_empty(dms)) {
		ret = hfi2_dms_impl_pio_sendv(dms, get_unaligned_le64(hdr),
					      spans, niov, true);
		if (ret != -EAGAIN)
			return ret;
	}

	/*
	 * Keep the packet's place among the other PIO packets: copy it into a
	 * waiter if it fits one, else leave the retry to the ULP.
	 */
	return _pio_waitlist_append_ulp(dms, get_unaligned_le64(hdr), spans,
					niov);
}


int hfi2_dms_ulp_add_eth_match(struct hfi2_dms *dms,
			       const struct hfi2_dms_ulp_match *match)
{
	u8 ulp_id;

	if (!dms || !match)
		return -EINVAL;

	ulp_id = match->ulp_id;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;

	/*
	 * Software-only: this records the match for hfi2_dms_ulp_classify() and
	 * programs NO hardware.  Hardware RSM steering to a dedicated per-ULP
	 * receive context (see bulksvc_rsm_reserve()/bulksvc_rsm_init()) is
	 * deferred pending a multi-hfisvc capability.
	 *
	 * One match slot per ulp_id: this OVERWRITES any existing rule for the
	 * same ulp_id (last writer wins).  ulp_id is centrally owned, so a ULP
	 * only ever replaces its own rule and cannot clobber another ULP's.
	 *
	 * Soft-RoCE caveat: a RoCEv2 match (udp_dport == htons(4791)) will
	 * divert those frames from the soft-RoCE provider (rxe) on this host;
	 * running both accelerated and soft RoCE simultaneously is unsupported.
	 */
	dms->eth_match[ulp_id] = *match;
	return 0;
}

void hfi2_dms_ulp_del_eth_match(struct hfi2_dms *dms, u8 ulp_id)
{
	if (!dms || ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return;

	dms->eth_match[ulp_id] = (struct hfi2_dms_ulp_match){0};
}

u8 hfi2_dms_ulp_classify(struct hfi2_dms *dms, const void *eth_hdr, u32 hdr_len)
{
	const struct ethhdr *eth = eth_hdr;
	__be16 ethertype;
	u8 ip_proto = 0;
	__be16 udp_dport = 0;
	u32 l3_off;
	u8 prio_best = 0;
	u8 ulp_best = 0;
	u8 i;

	if (!dms || !eth_hdr || hdr_len < sizeof(*eth))
		return 0;

	ethertype = eth->h_proto;
	l3_off = sizeof(*eth);

	/*
	 * Parse just enough of the L3/L4 header to evaluate the registered match
	 * rules.  Every read is bounds-checked against hdr_len; a truncated
	 * header leaves ip_proto/udp_dport at 0, which does not match a non-zero
	 * rule field, so such a frame is unclaimed (the function returns 0).
	 */
	if (ethertype == htons(ETH_P_IP) &&
	    hdr_len >= l3_off + sizeof(struct iphdr)) {
		const struct iphdr *ip4 =
			(const void *)((const u8 *)eth_hdr + l3_off);
		u32 ihl = ip4->ihl * 4u;

		/*
		 * Only trust the IPv4 fields once the captured header covers the
		 * full IHL (base header + any options).  A frame whose IHL
		 * advertises options beyond hdr_len is truncated; leaving
		 * ip_proto at 0 keeps it from matching an ip_proto rule, so such
		 * a frame stays unclaimed and is handed to the host network
		 * stack.
		 */
		if (ihl >= sizeof(struct iphdr) && hdr_len >= l3_off + ihl) {
			ip_proto = ip4->protocol;
			if (ip_proto == IPPROTO_UDP &&
			    hdr_len >= l3_off + ihl + sizeof(struct udphdr)) {
				const struct udphdr *udp = (const void *)
					((const u8 *)eth_hdr + l3_off + ihl);

				udp_dport = udp->dest;
			}
		}
	} else if (ethertype == htons(ETH_P_IPV6) &&
		   hdr_len >= l3_off + sizeof(struct ipv6hdr)) {
		const struct ipv6hdr *ip6 =
			(const void *)((const u8 *)eth_hdr + l3_off);

		ip_proto = ip6->nexthdr;
		if (ip_proto == IPPROTO_UDP &&
		    hdr_len >= l3_off + sizeof(*ip6) + sizeof(struct udphdr)) {
			const struct udphdr *udp = (const void *)
				((const u8 *)eth_hdr + l3_off + sizeof(*ip6));

			udp_dport = udp->dest;
		}
	}

	for (i = 1; i < HFI2_DMS_ULP_MAX; i++) {
		const struct hfi2_dms_ulp_match *m = &dms->eth_match[i];

		if (m->ulp_id == 0)
			continue;
		if (m->ethertype && m->ethertype != ethertype)
			continue;
		if (m->ip_proto && m->ip_proto != ip_proto)
			continue;
		if (m->udp_dport && m->udp_dport != udp_dport)
			continue;
		if (ulp_best == 0 || m->prio > prio_best) {
			prio_best = m->prio;
			ulp_best = m->ulp_id;
		}
	}

	/*
	 * 0 means "no ULP claims this frame": it belongs to the host network
	 * stack and the caller must hand it to the cn6k Ethernet netdev path
	 * (copy-into-skb), never drop it.  Eager forwarding is NOT required for
	 * that delivery.
	 */
	return ulp_best;
}

static int _poll_data_rcd(struct hfi2_dms *dms, u32 budget)
{
	DMS_BUG_ON(!dms);

	struct hfi2_ctxtdata *rcd = dms->rcd_data;
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const maxcnt = get_hdrq_cnt(rcd) * rsize;
	u32 const max_packets = min_t(u32, budget, rcd->rcvhdrq_cnt);
	u32 rhqoff = hfi2_rcd_head(rcd);
	__le32 *rhf_addr = _get_rhf_addr(rcd, rhqoff);
	u64 rhf = rhf_to_cpu(rhf_addr);
	u32 numpkt = 0;
	u64 start = dms_rdtsc();
	/*
	 * RoCE bypass frames land in eager buffers (DMS data packets use the
	 * expected/TID path and never do).  Track eager returns only for the
	 * bypass path so the eager ring does not stall RoCE RX.
	 */
	u8 updegr = 0;
	u32 etail = (u32)-1;

	while (_rhf_rcv_seq(rhf) == rcd->seq_cnt) {
		union hfi2_dms_16b_header *hdr;
		enum hfi2_dms_msg_type msg_type;
		u8 ulp_id, subtype;

		if (numpkt >= max_packets)
			break;

		if (!_rhf_is_valid_16b(rhf)) {
			_log_rhe_reason(dms, rcd, rhf, rhqoff, rsize);
			goto next_packet;
		}

		_dms_rhf_test(dms, rhf);
		hdr = _get_16b_hdr(rcd, rhf_addr, rhf);

		msg_type = hfi2_dms_impl_message_type_get(hdr);
		if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
			dms->counters.rx_received[msg_type]++;

		switch (msg_type) {
		case HFI2_DMS_MSG_TYPE_DATA:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA))
				hfi2_dms_handle_data(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REPLAY))
				hfi2_dms_handle_data(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE))
				hfi2_dms_handle_data_speculative(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START:
		case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
		case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
		case HFI2_DMS_MSG_TYPE_DATA_REQUEST:
		case HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY:
		case HFI2_DMS_MSG_TYPE_WRITE_START:
		case HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY:
		case HFI2_DMS_MSG_TYPE_WRITE_START_EAGER:
		case HFI2_DMS_MSG_TYPE_WRITE_START_TINY:
		case HFI2_DMS_MSG_TYPE_DATA_START:
		case HFI2_DMS_MSG_TYPE_DATA_START_EAGER:
		case HFI2_DMS_MSG_TYPE_ACK:
		case HFI2_DMS_MSG_TYPE_NACK:
		case HFI2_DMS_MSG_TYPE_STATUS_RESPONSE:
		case HFI2_DMS_MSG_TYPE_STATUS_REQUEST:
			dd_dev_warn(dms->dd,
				    "Received unexpected message type: %d\n",
				    msg_type);
			WARN_ON_ONCE(true);
			break;

		default:
			/*
			 * A non-native msg_type ordinal lands here.  Decode the
			 * ULP namespace: for a ULP packet (ulp_id != 0) the raw
			 * message byte carries the ulp_id in its high bits, so
			 * it is not a valid enum hfi2_dms_msg_type ordinal and
			 * must never index the msg_type-sized packet_drop table.
			 * Dispatch such packets to their ULP handler; a genuine
			 * unknown native ordinal is logged as an error below.
			 */
			if (WARN_ON_ONCE(hfi2_dms_16b_ulp_decode(hdr, &ulp_id,
								 &subtype)))
				break;
			if (ulp_id != 0) {
				u32 egr_idx = wfr_rhf_egr_index(rhf);
				u32 egr_offset = rhf_egr_buf_offset(rhf);
				void *ebuf = rhf_use_egr_bfr(rhf) ?
					(void *)((u64)rcd->egrbufs.rcvtids[egr_idx].addr +
						 egr_offset * RCV_BUF_BLOCK_SIZE) :
					NULL;
				struct hfi2_dms_ulp_rx const rx =
					_dms_build_ulp_rx(rcd, rhf, hdr, ebuf);

				hfi2_dms_ulp_dispatch_rx(dms, ulp_id, subtype,
							 &rx);
				break;
			}
			dd_dev_err(dms->dd,
				   "Received unknown message type: %d\n",
				   msg_type);
			break;
		}
next_packet:
		numpkt++;
		if (!(rhqoff & 0xff)) {
			hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, 0);
			updegr = 0;
		}

		if (++rcd->seq_cnt > RHF_MAX_SEQ)
			rcd->seq_cnt = 1;
		rhqoff += rsize;
		if (rhqoff >= maxcnt)
			rhqoff = 0;
		rhf_addr = _get_rhf_addr(rcd, rhqoff);
		rhf = rhf_to_cpu(rhf_addr);
	}

	hfi2_set_rcd_head(rcd, rhqoff);
	dms->counters.hdrq_drain_packet += dms_rdtsc() - start;

	if (numpkt > 0)
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, numpkt);

	return numpkt;
}

static bool _access_deferred_find(struct hfi2_dms *dms,
				  hfi2_dms_rift_key_t remote_rift_key,
				  u32 remote_lid)
{
	struct hfi2_dms_deferred_start *entry;

	list_for_each_entry(entry, &dms->access_deferred.active, node) {
		if (entry->op == HFI2_DMS_OP_RDMA_READ) {
			if (entry->read.metadata.rx_rift_key.value == remote_rift_key.value &&
			    entry->read.metadata.slid == remote_lid)
				return true;
		} else {
			if (entry->write.metadata.tx_rift_key.value == remote_rift_key.value &&
			    entry->write.metadata.slid == remote_lid)
				return true;
		}
	}
	return false;
}

static void _access_deferred_add(struct hfi2_dms *dms,
				 enum hfi2_dms_op op,
				 const void *metadata,
				 const void *params)
{
	struct hfi2_dms_deferred_start *entry;

	DMS_BUG_ON(!dms);

	if (list_empty(&dms->access_deferred.free)) {
		dms->counters.access_deferred_full++;
		if (op == HFI2_DMS_OP_RDMA_READ) {
			const struct hfi2_dms_read_start_metadata *m = metadata;
			const struct hfi2_dms_read_start_parameters *p = params;

			_nack_log(dms, HFI2_DMS_ERR_TYPE_RNR, p->dms_key);
			_inject_nack(dms, HFI2_DMS_MSG_TYPE_READ_START,
				     HFI2_DMS_ERR_TYPE_RNR,
				     m->port_idx, m->slid, m->rx_rift_key);
			dms->counters.rnr_nack_sent++;
		} else {
			const struct hfi2_dms_write_start_metadata *m = metadata;
			const struct hfi2_dms_write_start_parameters *p = params;

			_nack_log(dms, HFI2_DMS_ERR_TYPE_RNR, p->dms_key);
			_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START,
				     HFI2_DMS_ERR_TYPE_RNR,
				     m->port_idx, m->slid, m->tx_rift_key);
			dms->counters.rnr_nack_sent++;
		}
		return;
	}

	entry = list_first_entry(&dms->access_deferred.free,
				 struct hfi2_dms_deferred_start, node);
	list_del(&entry->node);

	entry->retries = 0;
	entry->op = op;
	if (op == HFI2_DMS_OP_RDMA_READ) {
		entry->read.metadata = *(const struct hfi2_dms_read_start_metadata *)metadata;
		entry->read.parameters = *(const struct hfi2_dms_read_start_parameters *)params;
	} else {
		entry->write.metadata = *(const struct hfi2_dms_write_start_metadata *)metadata;
		entry->write.parameters = *(const struct hfi2_dms_write_start_parameters *)params;
	}

	list_add_tail(&entry->node, &dms->access_deferred.active);
	dms->access_deferred.count++;
	dms->counters.access_deferred_count++;
}

static void _access_deferred_retry_all(struct hfi2_dms *dms)
{
	struct hfi2_dms_deferred_start *entry, *tmp;

	DMS_BUG_ON(!dms);

	if (list_empty(&dms->access_deferred.active))
		return;

	list_for_each_entry_safe(entry, tmp, &dms->access_deferred.active, node) {
		enum hfi2_dms_op saved_op = entry->op;
		int ret;

		if (entry->retries > HFI2_DMS_ACCESS_DEFERRED_MAX_RETRIES) {
			/* Deferred pool already covered the MR-reg race
			 * window; promote to fatal ACCESS_NOT_FOUND.
			 */
			if (entry->op == HFI2_DMS_OP_RDMA_READ) {
				_nack_log(dms, HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					  entry->read.parameters.dms_key);
				_inject_nack(dms, HFI2_DMS_MSG_TYPE_READ_START,
					     HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					     entry->read.metadata.port_idx, entry->read.metadata.slid,
					     entry->read.metadata.rx_rift_key);
			} else {
				_nack_log(dms, HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					  entry->write.parameters.dms_key);
				_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START,
					     HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					     entry->write.metadata.port_idx,
					     entry->write.metadata.slid,
					     entry->write.metadata.tx_rift_key);
			}
			list_del(&entry->node);
			entry->op = HFI2_DMS_OP_NONE;
			list_add_tail(&entry->node, &dms->access_deferred.free);
			dms->access_deferred.count--;
			dms->counters.access_deferred_nack++;
			dms->counters.access_deferred_nack_fatal++;
			continue;
		}

		if (entry->op == HFI2_DMS_OP_RDMA_READ)
			ret = hfi2_dms_impl_handle_read_start(dms,
				&entry->read.metadata,
				&entry->read.parameters, NULL);
		else
			ret = hfi2_dms_impl_handle_write_start(dms,
				&entry->write.metadata,
				&entry->write.parameters, NULL, NULL, 0);

		if (ret == 0) {
			list_del(&entry->node);
			entry->op = HFI2_DMS_OP_NONE;
			list_add_tail(&entry->node, &dms->access_deferred.free);
			dms->access_deferred.count--;
			dms->counters.access_deferred_retry_ok++;
		} else {
			entry->retries++;
		}
		(void)saved_op;
	}
}

#if HFI2_BULKSVC_ULP_STUBS
void hfi2_dms_eal_init_rcd(struct hfi2_dms *dms, struct hfi2_ctxtdata *rcd,
			   u8 pidx)
{
	u8 lb_pidx = loopback_pidx_dd(dms->dd, pidx);

	if (dms->dd->rcv_hdr_ent_size <= 2 ||
	    dms->dd->rcv_hdr_ent_size - 2 < HFI2_DMS_CTRL_HDR_SIZE)
		dd_dev_warn_ratelimited(dms->dd,
					"EAL HDRQ-inline prefix is shorter than the assumed EAL+TS+Eth/IPv4/UDP budget; frames may be dropped by header-budget checks\n");

	dms->rcd_ctrl = rcd;
	/* Program the same split on loopback without changing RoCE port state. */
	_dms_rcv_context_disable9B(dms, pidx, rcd);
	_set_split_point(dms, pidx, rcd, hfi2_dms_eth_bypass_hdr_dws(dms->dd));
	_dms_rcv_context_disable9B(dms, lb_pidx, rcd);
	_set_split_point(dms, lb_pidx, rcd, hfi2_dms_eth_bypass_hdr_dws(dms->dd));
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_ctrl;
}

int hfi2_dms_eal_poll(struct hfi2_dms *dms)
{
	return _poll_ctrl_rcd(dms, HFI2_DMS_PER_POLL_MAX_PACKETS);
}
#endif

static int _poll_ctrl_rcd(struct hfi2_dms *dms, u32 budget)
{
	DMS_BUG_ON(!dms);

	struct hfi2_ctxtdata *rcd = dms->rcd_ctrl;
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const maxcnt = get_hdrq_cnt(rcd) * rsize;
	u32 const max_packets = min_t(u32, budget, rcd->rcvhdrq_cnt);
	u32 rhqoff = hfi2_rcd_head(rcd);
	__le32 *rhf_addr = _get_rhf_addr(rcd, rhqoff);
	u64 rhf = rhf_to_cpu(rhf_addr);
	u64 start = dms_rdtsc();
	u32 numpkt = 0;
	u8 rcv_port;
	u8 updegr = 0;
	u32 etail = (u32)-1;

	while (_rhf_rcv_seq(rhf) == rcd->seq_cnt) {
		union hfi2_dms_16b_header *hdr;
		enum hfi2_dms_msg_type msg_type;
		void *ebuf = NULL;
		u32 egr_idx = wfr_rhf_egr_index(rhf);
		u32 egr_offset = rhf_egr_buf_offset(rhf);
		u32 prev_etail = etail;
		u8 prev_updegr = updegr;
		u8 ulp_id, subtype;

		if (numpkt >= max_packets)
			break;

		etail = egr_idx;
		updegr |= !(egr_idx & (rcd->egrbufs.threshold - 1)) && !egr_offset;

		/*
		 * Bypass frames do not carry native 16B framing, so intercept EAL
		 * Ethernet before the native-16B validity gate below.
		 */
		if (unlikely(rhf_rcv_type(rhf) == RHF_RCV_TYPE_BYPASS &&
			     hfi2_is_eth_mode(dms->dd))) {
			const struct eal_ingress_header *eal_hdr;
			struct hfi2_dms_ulp_rx rx;
			u8 eth_hdr[ETH_HLEN + sizeof(struct iphdr) +
				   MAX_IPOPTLEN + sizeof(struct udphdr)];
			u8 eth_ulp_id;
			u32 eth_hdr_len;
			u32 const header_budget = _eth_bypass_header_budget(rcd, rhf);
			u32 const hw_split = hfi2_dms_eth_bypass_hdr_dws(dms->dd) * sizeof(u32);
			bool const rhe_valid = _rhf_rhe_valid(rhf);
			u64 const err_flags = rhe_valid ? ((u64 *)rcd->rheq)[rhqoff / rsize] : 0;
			bool const tid_overrun = rhe_valid &&
				(err_flags & RHF_ERROR_SMASK) == RHF_TID_ERR;
			bool const valid_egr = rhf_use_egr_bfr(rhf) && rcd->egrbufs.rcvtids &&
				egr_idx < rcd->egrbufs.alloced &&
				rcd->egrbufs.rcvtids[egr_idx].addr;

			/* An overrun names the last filled slot; other frames must use one. */
			if (tid_overrun ? egr_idx >= rcd->egrbufs.alloced : !valid_egr) {
				etail = prev_etail;
				updegr = prev_updegr;
			}

			/* Drop errored bypass frames before parsing attacker-controlled bytes. */
			if (rhe_valid) {
				if (tid_overrun && egr_idx < rcd->egrbufs.alloced)
					updegr = 1;
				dms->counters.eal_bypass_rhe_error_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: RHF error bit set (rhf=0x%016llx)\n",
					 (unsigned long long)rhf);
				goto next_packet;
			}
			if (rhf_use_egr_bfr(rhf)) {
				if (unlikely(!valid_egr)) {
					dms->counters.eal_bypass_egr_bounds_drop++;
					dd_dev_warn_ratelimited
						(dms->dd,
						 "EAL bypass frame dropped: eager index %u invalid (alloced %u)\n",
						 egr_idx, rcd->egrbufs.alloced);
					goto next_packet;
				}
				ebuf = (void *)(((u64)(rcd->egrbufs.rcvtids[egr_idx].addr)) +
						(egr_offset * RCV_BUF_BLOCK_SIZE));
			}
			hdr = _get_16b_hdr(rcd, rhf_addr, rhf);
			eal_hdr = (const void *)hdr;
			if (header_budget < sizeof(*eal_hdr)) {
				dms->counters.eal_bypass_header_short_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: header_budget %u too small for EAL header (%zu)\n",
					 header_budget, sizeof(*eal_hdr));
				goto next_packet;
			}
			/* Eager data starts at the hardware split, not at header_budget. */
			if (header_budget < hw_split && rhf_pkt_len(rhf) > header_budget) {
				dms->counters.eal_bypass_header_short_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: header_budget %u smaller than the hardware split %u\n",
					 header_budget, hw_split);
				goto next_packet;
			}
			if (EAL_INGRESS_GET_L4(eal_hdr) != EAL_INGRESS_L4_ETHERNET ||
			    EAL_INGRESS_GET_TYPE(eal_hdr) != EAL_INGRESS_TYPE_ETHERNET) {
				dms->counters.eal_bypass_header_mismatch_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: unexpected L4/Type in EAL ingress header (L4=%llu Type=%llu)\n",
					 (unsigned long long)EAL_INGRESS_GET_L4(eal_hdr),
					 (unsigned long long)EAL_INGRESS_GET_TYPE(eal_hdr));
				goto next_packet;
			}
			if (!_dms_build_eth_ulp_rx(rcd, rhf, eal_hdr, ebuf, &rx)) {
				dms->counters.eal_bypass_ulp_build_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: failed to build ULP rx descriptor\n");
				goto next_packet;
			}

			eth_hdr_len = hfi2_dms_ulp_rx_copy_prefix(&rx, eth_hdr,
								  sizeof(eth_hdr));
			eth_ulp_id = hfi2_dms_ulp_classify(dms, eth_hdr, eth_hdr_len);
			if (eth_ulp_id)
				hfi2_dms_ulp_dispatch_rx(dms, eth_ulp_id, 0, &rx);
			else
				cne_ulp_fallthrough(dms, &rx);
			goto next_packet;
		}

		if (!_rhf_is_valid_16b(rhf)) {
			_log_rhe_reason(dms, rcd, rhf, rhqoff, rsize);
			goto next_packet;
		}

		if (rhf_use_egr_bfr(rhf)) {
			ebuf = (void *)(((u64)(rcd->egrbufs.rcvtids[egr_idx].addr)) +
					(egr_offset * RCV_BUF_BLOCK_SIZE));
		}

		_dms_rhf_test(dms, rhf);
		hdr = _get_16b_hdr(rcd, rhf_addr, rhf);
		rcv_port = _rhf_rcv_port(rhf);
		/* Native 16B framing cannot occur in eth mode; drop any hardware anomaly. */
		if (hfi2_is_eth_mode(dms->dd)) {
			dms->counters.eal_native16b_in_eth_mode_drop++;
			dd_dev_warn_ratelimited
				(dms->dd,
				 "Native 16B frame dropped in eth mode (rhf=0x%016llx)\n",
				 (unsigned long long)rhf);
			goto next_packet;
		}

		msg_type = hfi2_dms_impl_message_type_get(hdr);
		if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
			dms->counters.rx_received[msg_type]++;

		switch (msg_type) {
		case HFI2_DMS_MSG_TYPE_READ_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, false);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, true);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START_REPLAY))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, false);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REQUEST:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REQUEST))
				hfi2_dms_impl_handle_data_request_packet(dms, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY))
				hfi2_dms_impl_handle_data_request_packet(dms, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
								       false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
									false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_EAGER:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_EAGER))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
								       true, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_TINY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_TINY))
				hfi2_dms_impl_handle_write_start_tiny_packet(dms, rcv_port,
									     hdr);
			break;

		case HFI2_DMS_MSG_TYPE_ACK:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_ACK))
				hfi2_dms_impl_handle_ack(dms, hdr, HFI2_DMS_MSG_TYPE_ACK);
			break;

		case HFI2_DMS_MSG_TYPE_NACK:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_NACK))
				hfi2_dms_impl_handle_nack_packet(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_STATUS_RESPONSE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_STATUS_RESPONSE))
				hfi2_dms_impl_handle_status_response_packet(dms, rcv_port, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_STATUS_REQUEST:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_STATUS_REQUEST))
				hfi2_dms_impl_handle_status_request_packet(dms, rcv_port, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_START))
				hfi2_dms_handle_data_start_packet(dms, false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_START_EAGER:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_START_EAGER))
				hfi2_dms_handle_data_start_packet(dms, true, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_DATA:
		case HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE:
			dms->counters.ctrl_rcd_unexpected_data++;
			dd_dev_warn(dms->dd,
				    "Received unexpected message type: %d\n",
				    msg_type);
			WARN_ON_ONCE(true);
			break;

		default:
			/*
			 * A non-native msg_type ordinal lands here.  Decode the
			 * ULP namespace: for a ULP packet (ulp_id != 0) the raw
			 * message byte carries the ulp_id in its high bits, so
			 * it is not a valid enum hfi2_dms_msg_type ordinal and
			 * must never index the msg_type-sized packet_drop table.
			 * Dispatch such packets to their ULP handler; a genuine
			 * unknown native ordinal is logged as an error below.
			 */
			if (WARN_ON_ONCE(hfi2_dms_16b_ulp_decode(hdr, &ulp_id,
								 &subtype)))
				break;
			if (ulp_id != 0) {
				struct hfi2_dms_ulp_rx const rx =
					_dms_build_ulp_rx(rcd, rhf, hdr, ebuf);

				hfi2_dms_ulp_dispatch_rx(dms, ulp_id, subtype,
							 &rx);
				break;
			}
			dd_dev_err(dms->dd,
				   "Received unknown message type: %d\n",
				   msg_type);
			break;
		}
next_packet:
		numpkt++;
		if (!(rhqoff & 0xff)) {
			hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, 0);
			updegr = 0;
		}

		if (++rcd->seq_cnt > RHF_MAX_SEQ)
			rcd->seq_cnt = 1;
		rhqoff += rsize;
		if (rhqoff >= maxcnt)
			rhqoff = 0;
		rhf_addr = _get_rhf_addr(rcd, rhqoff);
		rhf = rhf_to_cpu(rhf_addr);
	}

	hfi2_set_rcd_head(rcd, rhqoff);
	dms->counters.hdrq_drain_packet += dms_rdtsc() - start;

	if (numpkt > 0)
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, numpkt);

	return numpkt;
}

static void _noop_handle_packet(struct hfi2_packet *packet)
{
	(void) packet;
}


static void hfi2_dms_impl_reclaim_ahg(struct hfi2_dms *dms, struct sdma_engine *sde, struct hfi2_dms_sde_rsrc *sde_rsrc)
{
	u32 descq_head;
	u32 descq_tail;
	struct hfi2_dms_ahg_header_set *ahg_header_set;
	u32 ahg_desc;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(sde == NULL);
	DMS_WARN_ON(sde_rsrc == NULL);

	descq_head = sde->descq_head;
	descq_tail = sde->descq_tail;
	if (descq_head == descq_tail) {
		// reclaim all
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	} else if (descq_head < descq_tail) {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc > descq_head && ahg_desc <= descq_tail) {
				// this is within our list and our headers
				// are in-order here so we can just stop
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	} else {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc <= descq_tail || ahg_desc > descq_head) {
				// tail has wrapped, so this is within our list
				// and we can stop searching
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	}
}

/*
 * Shared engines: other lanes advance the ring too, so a ring index cannot
 * tell this lane's in-flight header sets from ones that egressed a lap ago.
 * Compare the placed-descriptor count recorded with each set against the
 * engine's head on the same scale instead.  This lane's sets are queued in
 * placement order, so stop at the first one still in flight.
 */
static void hfi2_dms_impl_reclaim_ahg_shared(struct hfi2_dms *dms, u32 idx)
{
	struct hfi2_dms_sde_rsrc *sde_rsrc = &dms->sde_rsrcs[idx];
	struct sdma_engine *sde = dms->sdma_engines[idx];
	struct hfi2_dms_ahg_header_set *ahg_header_set;
	u64 head_seq;

	if (!sde_rsrc->active_ahg_headers.head)
		return;

	hfi2_dms_sde_lock(dms, idx);
	sdma_gethead_dma(sde);
	head_seq = hfi2_dms_sde_head_seq(dms, idx, sde->descq_tail,
					 READ_ONCE(sde->descq_head),
					 sde->descq_cnt);
	hfi2_dms_sde_unlock(dms, idx);

	while (sde_rsrc->active_ahg_headers.head) {
		ahg_header_set = (struct hfi2_dms_ahg_header_set *)
				 sde_rsrc->active_ahg_headers.head;
		if (ahg_header_set->seq_end > head_seq)
			break;
		hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
		hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_header_set->port_idx].free,
					   &ahg_header_set->dlist);
	}
}

static bool _tracker_is_stale(union hfi2_dms_tracker const * const tracker, ktime_t const now)
{
	return ktime_after(now, tracker->hdr.stale_time);
}

static bool _tracker_is_dead(union hfi2_dms_tracker const * const tracker, ktime_t const now)
{
	/*
	 * Dead if EITHER clock trips: progress stalled (odometer idle for
	 * PROGRESS_MAX_NS) or absolute lifetime exceeded. last_progress_time is
	 * refreshed on real byte progress, not peer-request arrival, so a
	 * status-polled but zero-progress chain-head is still reclaimed.
	 */
	bool const progress_stalled = ktime_after(now,
		ktime_add_ns(tracker->hdr.last_progress_time,
			     HFI2_DMS_TRACKER_PROGRESS_MAX_NS));
	bool const lifetime_exceeded = ktime_after(now,
		ktime_add_ns(tracker->hdr.birth_time,
			     HFI2_DMS_TRACKER_ABSOLUTE_MAX_NS));
	bool const res = progress_stalled || lifetime_exceeded;

	if (res) {
		pr_debug("(%d) Tracker is dead (l:%05u r:%05u); sr=%u odo=%llu\n",
			 __LINE__, tracker->hdr.local_rift_key.value,
			 tracker->hdr.remote_rift_key.value,
			 tracker->hdr.status_req_count,
			 tracker->hdr.byte_odometer);
	}
	return res;
}

static void hfi2_dms_poll_stale(struct hfi2_dms *dms)
{
	static int const err = -ETIMEDOUT;

	DMS_BUG_ON(!dms);

	ktime_t const now = dms->now;

	// remove any disabled tidsets
	u32 const sz = HFI2_DMS_ARRAY_SIZE(dms->read_requests);
	for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
		struct hfi2_dms_read_request_state *read_request = &dms->read_requests[tid_set];
		enum hfi2_dms_tidset_state const state = read_request->state;

		if (state == HFI2_DMS_TIDSET_STATE_DISABLED) {
			if (ktime_to_ns(ktime_sub(now, read_request->disable_ts)) > HFI2_DMS_FABRIC_PACKET_MAX_LIFETIME_NS) {
				dms->counters.health_tidset_disabled_removed++;
				dd_dev_dbg(dms->dd, "Removed disabled tidset read request\n");
				_tidset_free_then_poll_waiters(dms, tid_set);
			}
		} else if (state == HFI2_DMS_TIDSET_STATE_ENABLED) {
			if (ktime_after(now, read_request->stale_time)) {
				struct hfi2_dms_rx_tracker *rx_tracker = read_request->rx_tracker;
				DMS_BUG_ON(rx_tracker == &dms->disabled_rx_tracker);

				/* fast_fail cancels here, before the DRAINING
				 * re-arm would starve the tracker-level cancel.
				 */
				if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)
								  rx_tracker))
					continue;

				read_request->drain_count += 1;

				read_request->state = HFI2_DMS_TIDSET_STATE_DRAINING;
				/*
				 * The request is abandoned until re-injected:
				 * disarm its edge copy-out and stop DATA from
				 * landing in the bounce page meanwhile.
				 */
				if (dms->read_request_chunks[tid_set].scatter_count) {
					dms->read_request_chunks[tid_set].scatter_valid = false;
					_tidset_bounce_detach(dms, tid_set);
				}
				read_request->drain_time = ktime_add_ns(now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);

				_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * (HFI2_DMS_STALE_BACKOFF_BASE_MS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT)));

				dms->counters.health_tidset_draining++;
				dd_dev_dbg(dms->dd,
					"tidset DRAINING: tid_set %u (l:%05u r:%05u) drain_count=%u remaining_qws=%llu\n",
					tid_set, rx_tracker->hdr.local_rift_key.value,
					rx_tracker->hdr.remote_rift_key.value,
					read_request->drain_count, read_request->remaining_qws);
			}
		} else if (state == HFI2_DMS_TIDSET_STATE_DRAINING) {
			/*
			 * DRAINING tidset: drain timer has been set. When it
			 * expires, re-inject the DATA_REQUEST using saved
			 * parameters. The same tidset is reused (no disable,
			 * no fresh allocation). If drain_count exceeds max
			 * retries, disable the tidset and cancel the tracker.
			 */
			if (ktime_after(now, read_request->drain_time)) {
				struct hfi2_dms_rx_tracker *rx_tracker = read_request->rx_tracker;

				/* Backstop cancel for a DRAINING tidset that
				 * bypassed the ENABLED-arm cancel above.
				 */
				if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)
								  rx_tracker))
					continue;

				if (read_request->drain_count > HFI2_DMS_STALE_BACKOFF_MAX_COUNT) {
					/* Drained-out unlatched speculative read
					 * falls back to legacy READ_START.
					 */
					if (_rx_tracker_spec_unlatched(rx_tracker)) {
						_dms_rx_spec_fallback_to_legacy(dms, rx_tracker);
						continue;
					}
					/* Exceeded max retries - give up on this tidset and cancel the tracker */
					dms->counters.health_tidset_drain_failed++;
					dd_dev_dbg(dms->dd,
						"tidset DRAIN FAILED: tid_set %u (l:%05u r:%05u) drain_count=%u > max=%u - canceling tracker\n",
						tid_set, rx_tracker->hdr.local_rift_key.value,
						rx_tracker->hdr.remote_rift_key.value,
						read_request->drain_count,
						(u32)HFI2_DMS_STALE_BACKOFF_MAX_COUNT);
					hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -ETIMEDOUT);
					continue;
				}

				struct hfi2_dms_read_request_chunks *rc =
					&dms->read_request_chunks[tid_set];
				int ret;
				read_request->generation += 1;

				/*
				 * The re-request re-sends the whole saved request, so
				 * re-arm its edge copy-out for the new generation and
				 * remap the bounce pair before the responder can send.
				 */
				if (rc->scatter_count) {
					rc->scatter_generation = read_request->generation;
					rc->scatter_valid = true;
					_tidset_bounce_attach(dms, tid_set);
				}

				ret = _inject_data_request_replay(dms, tid_set);
				if (ret < 0) {
					if (rc->scatter_count) {
						rc->scatter_valid = false;
						_tidset_bounce_detach(dms, tid_set);
					}
					read_request->generation -= 1;
					dms->counters.health_tidset_drain_reinject_fail++;
					dd_dev_dbg(dms->dd,
						"tidset DRAIN re-inject failed: tid_set %u ret=%d\n",
						tid_set, ret);
					/* Retry on next poll cycle */
					read_request->drain_time = ktime_add_ns(now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);
					continue;
				}

				dms->counters.health_tidset_drain_reinject++;
				dd_dev_dbg(dms->dd,
					"tidset DRAIN re-inject: tid_set %u (l:%05u r:%05u) drain_count=%u\n",
					tid_set, rx_tracker->hdr.local_rift_key.value,
					rx_tracker->hdr.remote_rift_key.value,
					read_request->drain_count);

				read_request->remaining_qws = read_request->total_requested_qws;
				read_request->state = HFI2_DMS_TIDSET_STATE_ENABLED;

				u64 stale_backoff_ns = HFI2_DMS_TIDSET_STALE_TIMEOUT_NS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT);
				read_request->stale_time = ktime_add_ns(now, stale_backoff_ns);

				_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * (HFI2_DMS_STALE_BACKOFF_BASE_MS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT)));
			}
		}
	}

	/* check stale/dead active trackers — batch by remote LID */
	DECLARE_BITMAP(visited, HFI2_DMS_RIFT_IDX_SIZE);
	bitmap_zero(visited, HFI2_DMS_RIFT_IDX_SIZE);
	hfi2_dms_rift_key_t entries[HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES];

	unsigned long idx;
	for_each_set_bit(idx, dms->rift.occupied, HFI2_DMS_RIFT_IDX_SIZE) {
		union hfi2_dms_tracker *tracker;

		if (test_bit(idx, visited))
			continue;

		tracker = dms->rift.arr[idx];

		if (!_tracker_is_stale(tracker, now))
			continue;

		_tracker_note_progress(dms, tracker);
		if (_tracker_is_dead(tracker, now)) {
			/*
			 * The tracker-dead clock is a fixed deadline independent
			 * of the drain-retry cadence, so under a raised
			 * bulksvc_dms_health_base it can fire before the tidset
			 * drain arm runs its legacy fallback. Recover an unlatched
			 * speculative read here too (unless fast_fail) rather than
			 * forfeit recovery to -ETIMEDOUT.
			 */
			if (_rx_tracker_spec_unlatched(&tracker->rx) &&
			    !tracker->hdr.fast_fail) {
				_dms_rx_spec_fallback_to_legacy(dms, &tracker->rx);
				continue;
			}
			dms->counters.health_tracker_dead++;
			_tracker_cancel(dms, tracker, err);
			continue;
		}

		/*
		 * A fast_fail tracker defers retransmission to its caller: once
		 * stale, cancel to -ETIMEDOUT instead of emitting a STATUS_REQUEST.
		 * A READ target awaiting its DATA_REQUEST probes initiator instead.
		 */
		if (_tx_tracker_is_read_target_awaiting_data_req(tracker))
			dms->counters.health_status_req_fast_fail_read_target++;
		else if (_tracker_cancel_if_fast_fail(dms, tracker))
			continue;

		u32 const lid = tracker->hdr.remote_lid;
		u8 const port_idx = tracker->hdr.port_idx;

		set_bit(idx, visited);
		u8 n_entries = 0;

		if (tracker->hdr.rnr_pending) {
			tracker->hdr.rnr_pending = false;
			if (_tracker_cancel_if_fast_fail(dms, tracker))
				continue;
			_tracker_reinject_start(dms, tracker);
		} else {
			entries[n_entries++] = tracker->hdr.local_rift_key;
		}
		_update_tracker_backoff(dms, tracker);

		unsigned long next = idx + 1;
		for_each_set_bit_from(next, dms->rift.occupied, HFI2_DMS_RIFT_IDX_SIZE) {
			union hfi2_dms_tracker *next_tracker;

			if (test_bit(next, visited))
				continue;

			next_tracker = dms->rift.arr[next];
			if (next_tracker->hdr.remote_lid != lid ||
			    next_tracker->hdr.port_idx != port_idx)
				continue;

			set_bit(next, visited);

			if (!_tracker_is_stale(next_tracker, now))
				continue;

			_tracker_note_progress(dms, next_tracker);
			if (_tracker_is_dead(next_tracker, now)) {
				/* Same unlatched-speculative recovery as the head
				 * tracker above: prefer legacy fallback over an
				 * -ETIMEDOUT cancel when the dead clock beats the
				 * drain arm (unless fast_fail).
				 */
				if (_rx_tracker_spec_unlatched(&next_tracker->rx) &&
				    !next_tracker->hdr.fast_fail) {
					_dms_rx_spec_fallback_to_legacy(dms, &next_tracker->rx);
					continue;
				}
				dms->counters.health_tracker_dead++;
				_tracker_cancel(dms, next_tracker, err);
				continue;
			}

			if (_tx_tracker_is_read_target_awaiting_data_req(next_tracker))
				dms->counters.health_status_req_fast_fail_read_target++;
			else if (_tracker_cancel_if_fast_fail(dms, next_tracker))
				continue;

			if (next_tracker->hdr.rnr_pending) {
				next_tracker->hdr.rnr_pending = false;
				if (_tracker_cancel_if_fast_fail(dms, next_tracker))
					continue;
				_tracker_reinject_start(dms, next_tracker);
			} else {
				entries[n_entries++] = next_tracker->hdr.local_rift_key;
			}
			_update_tracker_backoff(dms, next_tracker);

			if (n_entries == HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES) {
				_inject_status_request_many(dms, port_idx, lid,
							    entries, n_entries);
				n_entries = 0;
			}
		}

		if (n_entries > 0)
			_inject_status_request_many(dms, port_idx, lid,
						    entries, n_entries);
	}

	ktime_t aging_deadline = ktime_add_ms(dms->cancel_cache.last_aging_time, 5000);
	if (ktime_after(now, aging_deadline)) {
		_cancel_cache_age(dms, now);
		dms->cancel_cache.last_aging_time = now;
	}
}

static void _dms_drain_workqueue(struct hfi2_dms *dms)
{
	ktime_t now = dms->now;

	if (dms->work_items.active.head) {
		struct hfi2_dms_work_item *item, *next_item;

		item = (struct hfi2_dms_work_item *)dms->work_items.active.head;
		while (item) {
			next_item = (struct hfi2_dms_work_item *)item->dlist.next;
			if (item->work_fn(dms, item) != -EAGAIN) {
				hfi2_dms_impl_work_item_free(dms, item);
			} else {
				/*
				 * Signed: now is sampled when the poll starts, so an
				 * item queued later in the same pass has a negative
				 * age. Unsigned, that wrapped past the limit and the
				 * item was dropped on its first -EAGAIN.
				 */
				s64 elapsed_ns = ktime_to_ns(ktime_sub(now, item->enqueue_time));

				if (elapsed_ns > HFI2_DMS_WORK_ITEM_MAX_RETRY_TIME_NS) {
					dd_dev_err(dms->dd,
						   "DMS work item failed after max retry time, discarding.\n");
					hfi2_dms_impl_work_item_free(dms, item);
				}
			}
			item = next_item;
		}
	}
}

int hfi2_dms_poll(struct hfi2_dms *dms, ktime_t const now)
{
	int numpkt = 0;
	u64 start;
	u64 end;
	int i;

	dms->now = now;
	start = dms_rdtsc();
	dms_trace(dms_poll, dms);

	for (i = 0; i < dms->num_engines; ++i) {
		if (dms->sde_share) {
			hfi2_dms_impl_reclaim_ahg_shared(dms, i);
			continue;
		}
		sdma_gethead_dma(dms->sdma_engines[i]);
		hfi2_dms_impl_reclaim_ahg(dms, dms->sdma_engines[i], &dms->sde_rsrcs[i]);
	}
	_sdma_engine_waitlist_poll_all(dms);
	_dms_drain_workqueue(dms);
	numpkt += _pio_waitlist_poll(dms);

	ktime_t next_stale_check = ktime_add_ms(dms->last_stale_check, HFI2_DMS_STALE_POLL_TIME_MS);
	if (ktime_after(now, next_stale_check)) {
		dms->last_stale_check = now;
		hfi2_dms_poll_stale(dms);
	}

	/*
	 * Retry any rx_trackers waiting for tidsets after demand pinning.
	 * The pin queue (serviced by bulksvc just before dms_poll) may
	 * have pinned pages that allow previously-deferred tidset
	 * allocations to succeed now.
	 */
	_service_global_tidset_waiters(dms);

	_access_deferred_retry_all(dms);

	{
		int ctrl_n, data_n;
		int remaining = HFI2_DMS_POLL_TOTAL_PACKET_BUDGET;

		_access_deferred_retry_all(dms);

		do {
			int budget;

			ctrl_n = 0;
			data_n = 0;
			budget = min_t(int, HFI2_DMS_PER_POLL_MAX_PACKETS, remaining);
			if (budget <= 0)
				break;

			ctrl_n = _poll_ctrl_rcd(dms, budget);
			remaining -= ctrl_n;

			data_n = _poll_data_rcd(dms, min_t(int, HFI2_DMS_PER_POLL_MAX_PACKETS, remaining));
			remaining -= data_n;
			numpkt += ctrl_n + data_n;
		} while (ctrl_n + data_n > 0);
	}

	/*
	 * Service rift-poll requests deferred by completion/cancel bodies that
	 * ran nested inside a drive stack. Run before the SDMA drain below so a
	 * tracker driven here egresses its SDMA this same pass. A poll can
	 * itself defer another via an inline completion, so loop until quiet.
	 */
	while (dms->rift.poll_deferred) {
		dms->rift.poll_deferred = false;
		_dms_rift_poll(dms);
	}

	/*
	 * Drain each engine once per poll pass, decoupled from the RX loop
	 * above: batch_commit() only queues onto sde_rsrcs.sdma_pending, and
	 * ring placement + completion firing happen here, so a batch a ULP
	 * committed with no inbound RX still egresses and returns its cookie
	 * this pass.
	 */
	for (i = 0; i < dms->num_engines; ++i)
		numpkt += hfi2_dms_sdma_drain_and_complete(dms, (u8)i);

	while (dms->rift.poll_deferred) {
		dms->rift.poll_deferred = false;
		_dms_rift_poll(dms);
	}

	/*
	 * Packets still waiting for PIO credits or an in-flight P2P flush read
	 * keep the poll busy: nothing else wakes the event loop when the send
	 * context returns credits or the SDMA flush descriptor retires.
	 */
	numpkt += _pio_waitlist_poll(dms);
	if (!_pio_waitlist_empty(dms) || dms->p2p_flush_inflight)
		numpkt++;

	end = dms_rdtsc();
	dms->counters.hdrq_drain += end - start;

	return numpkt;
}

static void hfi2_dms_handle_tx_tracker_completion(struct hfi2_dms *dms, hfi2_dms_rift_key_t tx_rift_key, u16 flags)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(_rift_key_error(tx_rift_key));
	DMS_BUG_ON(!_rift_key_side_tx(tx_rift_key));

	struct hfi2_dms_tx_tracker *tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, tx_rift_key);
	if (!tx_tracker) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	tx_tracker->hdr.perf.lifetime[1] = ktime_get();
	_dms_aggregate_perf_counters(dms, (union hfi2_dms_tracker *)tx_tracker);
#endif

	_tracker_rift_release(dms, (union hfi2_dms_tracker *)tx_tracker, &dms->rift);

	/* Parent signals to child upon tx completion. */
	_tracker_signal(dms, (union hfi2_dms_tracker *)tx_tracker, 0);

	// invoke callback for the completed tx tracker
	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, (union hfi2_dms_tracker *)tx_tracker, flags, tx_tracker->read.parameters.imm_data, tx_tracker->hdr.order_key, 0);
		tx_tracker->read.access = NULL;

	} else if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, 0);
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);

	/*
	 * Hand the freed rift key on once this tracker is retired, but defer
	 * the poll: this completion can run nested inside a rift-poll drive.
	 */
	_dms_rift_poll_request(dms);
}

/**
 * These functions exist in some form in hfi2.h but they don't exist in the way
 * we really want them here. Convenience functions for our pre-defined
 * templates
 */
static u64 hfi2_dms_impl_pbc_template_create_16Bc(u8 port_idx, u32 dw_len, u16 sctxt)
{
	u64 ret;

	ret = (u64) sctxt << PBC_SEND_CTXT_SHIFT |
		(u64) PBC_L2_16B << PBC_L2_TYPE_SHIFT |
		(u64) port_idx << PBC_PORT_IDX_SHIFT |
		(u64) (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT |
		(u64) PBC_IHCRC_LKDETH << PBC_INSERT_HCRC_SHIFT |
		(u64) 1 << 19 | // 16B Compressed
		(u64) PBC_INSERT_BYPASS_ICRC; // InsertNon9BIcrc
	return ret;
}

static int hfi2_dms_impl_proto_command_template_make(struct hfi2_dms *dms, union hfi2_dms_proto_cmd *cmd, u8 port_idx, enum hfi2_dms_msg_type msg_type, u32 pkt_len_qws, u16 jkey)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);
	// Even though the PBC gets stripped, a 16b compressed header will expand by 1 QW as it goes
	// out on the wire, so actually the pktlen_dw in the pbc should be the same as pktlen_qw in the lrh
	cmd->pbc = hfi2_dms_impl_pbc_template_create_16Bc(port_idx, pkt_len_qws << 1, dms->port_sctxts[port_idx]->hw_context);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	cmd->bth[0] = HFI2_DMS_BTH_OPCODE | ((u32) msg_type << 16);
	cmd->bth[1] = (u32) RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; // set KVER
	cmd->kdeth[1] = jkey;

	return 0;
}

void hfi2_dms_impl_fill_proto_templates(struct hfi2_dms *dms)
{
	union hfi2_dms_proto_cmd *cmd;

	DMS_BUG_ON(dms == NULL);

	for (int i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		if (!dms->port_available[i])
			continue;

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_READ_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_READ_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_READ_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);
		_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
			_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
		}

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_READ_START_REPLAY;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
			_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
		}

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_DATA_REQUEST;
			u64 const size_qws = _pkt_len_qws(t, 0);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_CTRL_JKEY);
		}

		{
			enum hfi2_dms_msg_type const t =
				HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY;
			u64 const size_qws =
				_pkt_len_qws(t, 0);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA_START_EAGER];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA_START_EAGER,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START_EAGER] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA, sizeof(union hfi2_dms_proto_pkt_data)/sizeof(u64), HFI2_DMS_DATA_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_DATA_REPLAY;
			u64 const size_qws =
				sizeof(union hfi2_dms_proto_pkt_data) / sizeof(u64);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_DATA_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates
			[i][HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i,
							  HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE,
			sizeof(union hfi2_dms_proto_pkt_data) / sizeof(u64), HFI2_DMS_DATA_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_WRITE_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_WRITE_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_WRITE_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_WRITE_START_EAGER];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_WRITE_START_EAGER,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_WRITE_START_EAGER] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_WRITE_START_TINY;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t,
								  _pkt_len_qws(t, 0),
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_ACK];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_ACK, sizeof(union hfi2_dms_proto_pkt_ack)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_NACK];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_NACK, sizeof(union hfi2_dms_pkt_nack)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_STATUS_RESPONSE];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_STATUS_RESPONSE, sizeof(union hfi2_dms_pkt_status)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_STATUS_REQUEST];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_STATUS_REQUEST, sizeof(union hfi2_dms_pkt_status_request)/sizeof(u64), HFI2_DMS_CTRL_JKEY);
	}

}

/* This is effectively `hfi2_set_ctxt_pkey` but allowing us to set these values on the loopback
 * ports even when not in SRIOV mode
 */
static int _dms_set_ctxt_pkey(struct hfi2_devdata *dd, struct send_context *sc, u8 pidx, u16 pkey)
{
	u64 reg;

	if (!sc)
		return -EINVAL;

	reg = ((u64) pkey & SEND_CTXT_CHECK_PARTITION_KEY_VALUE_MASK)
		<< SEND_CTXT_CHECK_PARTITION_KEY_VALUE_SHIFT;
	write_epsc_csr(dd, pidx, sc->hw_context, dd->params->send_ctxt_check_partition_key_reg, reg);
	dd->params->set_pio_integrity(dd, pidx, sc->hw_context, sc->type, SPI_SET_PKEY);
	return 0;
}

// put somewhere common later
static inline u32 rcvarray_offset(u32 ctxt, u32 index, u32 type)
{
	u32 ret;
/* RcvArray access shifts. These are the same between JKR and CYR */
#define JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT 25
#define JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT 17
#define JKR_RCV_ARRAY_CSR_INDEX_SHIFT 3
	ret = (type == PT_EAGER ? 0 : BIT(JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT))
	       | (ctxt_bar_ctxt(ctxt) << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT)
	       | (index << JKR_RCV_ARRAY_CSR_INDEX_SHIFT);
	return ret;
}

/*
 * Caller invariant: dma_addrs[0..npages-1] are all non-zero.  The only
 * reachable runtime failure mode is dma_addrs[i] == 0, which is a page-
 * provider consistency violation and is now caught by the caller before
 * any tracker side effect is committed.  Programming-error checks remain
 * as DMS_BUG_ONs.  See _tidset_enable() for the validation contract.
 */
static void hfi2_dms_impl_map_tid_entries(struct hfi2_dms *dms,
					  dma_addr_t const *dma_addrs,
					  u64 npages,
					  u32 tid_set)
{
	u64 start;
	u64 tid_entries[HFI2_DMS_TID_SET_SIZE * 2] = {0};
	u64 tid_start;
	u64 tid_entry_start;
	u64 npages_twos;
	size_t i;
	dma_addr_t next_phys_addr;
	u64 csr_offset;
	u64 end;

	dms_trace(dms_map_tid_entries, dms, dma_addrs, npages, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(dma_addrs == NULL);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(npages == 0);
	DMS_BUG_ON(npages > (HFI2_DMS_TID_SET_SIZE*2));
	start = dms_rdtsc();

	tid_start = tid_set * HFI2_DMS_TID_SET_SIZE;
	tid_entry_start = tid_start * 2;

	npages_twos = (npages + 1) & ~1ull;

	for (i = 0; i < npages; ++i) {
		next_phys_addr = dma_addrs[i];
		DMS_BUG_ON(next_phys_addr == 0);
		tid_entries[i] = (u64) (next_phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}
	if (npages & 1) {
		tid_entries[npages] = (u64) (dms->zero_page.phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}
	flush_wc();
	end = dms_rdtsc();
	dms->counters.map_tids += end - start;
}

static void tidset_load_clear(struct hfi2_dms *dms, u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	rc->load_npages = 0;
	rc->load_nchunks = 0;
	rc->load_ngather = 0;
	rc->scatter_count = 0;
	rc->scatter_valid = false;
	rc->cycle_real_bytes = 0;
}

/*
 * Load one page-provider run into the tidset as a new recv_chunk: @len bytes
 * starting @page_offset bytes into @dma_pages[0], requested from source offset
 * @sbuf_offset as the chunk's single gather element. Each page maps to one
 * RcvArray entry; the chunk's tid_info names the chunk's first TID and carries
 * @page_offset (as dwords) so the responder's DATA lands at that offset within
 * it. Returns the bytes loaded, which is short of @len when the tidset has no
 * RcvArray entries (or recv_chunks / gather elements) left. Once a bounce edge
 * is loaded, the last TID pair and one recv_chunk stay reserved for it.
 */
static u64 tidset_load(struct hfi2_dms *dms, u32 tid_set, u32 sbuf_offset,
		       dma_addr_t const *dma_pages, u64 page_offset, u64 len)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];
	struct hfi2_dms_recv_chunk *chunk;
	struct hfi2_dms_gather *gather;
	u16 base_tid;
	u64 pages;
	u64 loaded;
	u64 i;

	u32 const bounce = rc->scatter_count ? 1 : 0;
	u32 const entries = HFI2_DMS_TID_SET_PAGES_MAX - 2 * bounce;

	if (rc->load_nchunks + bounce >= HFI2_DMS_DR_MAX_CHUNKS ||
	    rc->load_ngather + rc->scatter_count >= HFI2_DMS_DR_MAX_GATHER ||
	    rc->load_npages >= entries)
		return 0;
	pages = min(DIV_ROUND_UP(page_offset + len, (u64)PAGE_SIZE),
		    (u64)(entries - rc->load_npages));
	if (!pages)
		return 0;
	loaded = min(len, pages * PAGE_SIZE - page_offset);

	base_tid = tid_set * HFI2_DMS_TID_SET_SIZE + (rc->load_npages / 2);
	chunk = &rc->chunk[rc->load_nchunks++];
	chunk->tid_info = hfi2_dms_tid_info_make(base_tid, page_offset >> 2);
	chunk->length_count = FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, loaded) |
			      FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, 1);
	gather = &rc->gather[rc->load_ngather++];
	gather->sbuf_offset = sbuf_offset;
	gather->length = loaded;

	for (i = 0; i < pages; ++i)
		rc->load_dma[rc->load_npages + i] = dma_pages[i];
	rc->load_npages += pages;

	return loaded;
}

/*
 * Pad a dangling upper slot to the inert zero page so the next recv_chunk
 * starts on a TID (even-slot) boundary. The responder never sends into it
 * (bounded by the chunk length) and expected-receive never matches it.
 */
static void tidset_load_pad(struct hfi2_dms *dms, u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	if ((rc->load_npages & 1) &&
	    rc->load_npages < HFI2_DMS_TID_SET_PAGES_MAX) {
		rc->load_dma[rc->load_npages] = dms->zero_page.phys_addr;
		rc->load_npages += 1;
	}
}

/*
 * Record a sub-quadword destination edge of @len bytes, requested from
 * @sbuf_offset, for the tidset's bounce recv_chunk; completion copies it to
 * @dest_offset. The first edge reserves the tidset's last TID pair and one
 * recv_chunk. Returns false, loading nothing, when the tidset has no room.
 */
static bool tidset_load_edge(struct hfi2_dms *dms, u32 tid_set, u32 sbuf_offset,
			     u64 dest_offset, u8 len)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];
	struct hfi2_dms_bounce_scatter *s;

	if (rc->scatter_count >= HFI2_DMS_DR_CHUNK_MAX_GATHER ||
	    rc->load_ngather + rc->scatter_count >= HFI2_DMS_DR_MAX_GATHER)
		return false;
	if (!rc->scatter_count &&
	    (rc->load_nchunks >= HFI2_DMS_DR_MAX_CHUNKS ||
	     ALIGN(rc->load_npages, 2) > HFI2_DMS_TID_SET_PAGES_MAX - 2))
		return false;

	s = &rc->scatter[rc->scatter_count];
	s->dest_offset = dest_offset;
	s->sbuf_offset = sbuf_offset;
	s->bounce_offset = rc->scatter_count * sizeof(u64);
	s->length = len;
	rc->scatter_count++;
	return true;
}

/*
 * Program the tidset's RcvArray with the loaded TID pairs and, when the request
 * has edges, map the bounce page at the last TID pair. Also appends the bounce
 * recv_chunk and its gather elements after the direct ones.
 *
 * As before the tidset load API, only the entries this request uses are
 * written; the responder never sends past a chunk's length, so the rest are
 * never targeted. Writing all 32 on every enable costs up to 30 extra
 * uncached RcvArray writes per DATA_REQUEST.
 */
static noinline_for_stack void tidset_load_complete(struct hfi2_dms *dms,
						    u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	if (rc->load_npages)
		hfi2_dms_impl_map_tid_entries(dms, rc->load_dma,
					      rc->load_npages, tid_set);

	if (rc->scatter_count) {
		struct hfi2_dms_recv_chunk *chunk = &rc->chunk[rc->load_nchunks++];
		u32 real = 0;

		for (u8 i = 0; i < rc->scatter_count; i++) {
			rc->gather[rc->load_ngather++] = (struct hfi2_dms_gather){
				.sbuf_offset = rc->scatter[i].sbuf_offset,
				.length = rc->scatter[i].length,
			};
			real += rc->scatter[i].length;
		}
		chunk->tid_info = hfi2_dms_tid_info_make(tid_set * HFI2_DMS_TID_SET_SIZE +
							 HFI2_DMS_TID_SET_SIZE - 1, 0);
		chunk->length_count =
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, real) |
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, rc->scatter_count);
		_tidset_bounce_attach(dms, tid_set);
	}
}

static void _tidset_reset(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_tidset_state new_state)
{
	u64 const npages = HFI2_DMS_TID_SET_SIZE*2;
	u64 const npages_twos = (npages + 1) & ~1ull;
	u64 const tid_start = tid_set * HFI2_DMS_TID_SET_SIZE;
	u64 const tid_entry_start = tid_start * 2;

	u64 csr_offset;
	u64 tid_entries[HFI2_DMS_TID_SET_SIZE * 2] = {0};

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);

	dms->read_requests[tid_set].disable_ts = dms->now;
	dms->read_requests[tid_set].state = new_state;
	/* A reset request never completes, so its edges are never copied out. */
	if (dms->read_requests[tid_set].has_bounce) {
		dms->read_request_chunks[tid_set].scatter_valid = false;
		dms->read_request_chunks[tid_set].scatter_count = 0;
		dms->read_requests[tid_set].has_bounce = false;
	}
	dms->read_requests[tid_set].total_requested_qws = (u64)(-1);
	dms->read_requests[tid_set].remaining_qws = (u64)(-1);
	dms->read_requests[tid_set].rx_tracker = &dms->disabled_rx_tracker;

	for (u64 i = 0; i < npages; ++i) {
		tid_entries[i] = (u64) (dms->zero_page.phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (u64 i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}

	/*
	 * No flush_wc() here: _tidset_reset only programs the RcvArray entries.
	 * On the FREE path the next _tidset_enable() reprograms these same
	 * entries and flushes in hfi2_dms_impl_map_tid_entries(). On the DISABLED
	 * (quarantine) path the caller flushes once after resetting all of the
	 * tracker's tidsets, so the zero-page redirect is made visible without a
	 * redundant per-tidset sfence on the completion hot path.
	 */
}

int _tidset_enable(struct hfi2_dms *dms, u32 tid_set, struct hfi2_dms_rx_tracker *rx_tracker, u32 *tid_info, u64 *tidset_nbytes)
{
	struct hfi2_dms_read_request_chunks *rc;
	struct hfi2_dms_read_request_state *read_req_state;
	struct hfi2_dms_run runs[HFI2_DMS_TIDSET_RUNS_MAX];
	u64 payload_start;
	u64 cursor;
	u64 remaining;
	u64 packed_bytes = 0;
	u64 placed_bytes = 0;
	bool spec_charged;
	u32 read_size_qw;
	int nruns;
	u16 gen;
	int i;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(dms->read_requests[tid_set].tid_set != tid_set);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(!tid_info);
	DMS_BUG_ON(!tidset_nbytes);

	DMS_WARN_ON(rx_tracker->total_payload == rx_tracker->sbuf_cursor);

	/* Any alignment: the run split below lands sub-quadword edges. */
	payload_start = rx_tracker->rbuf_start_offset + rx_tracker->sbuf_cursor;

	/*
	 * Load the tidset from the destination's page-provider runs: fetch them
	 * with one get_runs() call, which also makes the pages resident, and
	 * load each run as its own recv_chunk until the tidset is full. This is
	 * the same for READ and WRITE and for one or many providers; a single
	 * MR is simply one run. The source is read linearly, so each chunk's
	 * sbuf_offset advances by the bytes already loaded.
	 *
	 * TID expected-receive lands only whole, quadword-aligned quadwords, so
	 * a run splits into a sub-quadword head up to its first quadword
	 * boundary, a quadword-aligned middle loaded directly, and a
	 * sub-quadword tail. The head and tail edges go to the bounce recv_chunk
	 * and are copied to the destination at completion. Fragments are taken
	 * strictly in order; the first one that does not fit ends the request,
	 * and the next request starts there.
	 */
	cursor = payload_start;
	remaining = rx_tracker->total_payload - rx_tracker->sbuf_cursor;

	if (WARN_ON(!rx_tracker->page_provider.get_runs))
		return -EFAULT;

	tidset_load_clear(dms, tid_set);

	/*
	 * Writable: hardware writes inbound data here. All failures are
	 * normalized to -EAGAIN so the tidset waiter loop in
	 * hfi2_dms_impl_make_data_request treats them as transient; any other
	 * than memory pressure is counted and logged, since it will not clear
	 * on its own.
	 */
	nruns = rx_tracker->page_provider.get_runs(&rx_tracker->page_provider,
						   payload_start, remaining,
						   true, runs,
						   HFI2_DMS_TIDSET_RUNS_MAX);
	if (nruns <= 0 || WARN_ON_ONCE(nruns > HFI2_DMS_TIDSET_RUNS_MAX)) {
		if (nruns != -EAGAIN && nruns != -ENOMEM) {
			dms->counters.health_tidset_run_fail++;
			dd_dev_warn_ratelimited(dms->dd,
						"DMS_DIAG: tidset get_runs failed ret=%d key=%05u off=%llu rem=%llu\n",
						nruns,
						rx_tracker->hdr.local_rift_key.value,
						payload_start, remaining);
		}
		return -EAGAIN;
	}

	for (i = 0; i < nruns && remaining; i++) {
		struct hfi2_dms_run const src = runs[i];
		u64 head, mid, tail, loaded;

		if (WARN_ON_ONCE(!src.run_bytes))
			return -EINVAL;

		head = min_t(u64, src.run_bytes, -src.page_offset & 7);
		mid = round_down(src.run_bytes - head, 8);
		tail = src.run_bytes - head - mid;

		if (head) {
			if (!tidset_load_edge(dms, tid_set,
					      rx_tracker->sbuf_cursor + packed_bytes,
					      cursor, head))
				break;
			packed_bytes += head;
			placed_bytes += sizeof(u64);
			cursor += head;
			remaining -= head;
		}

		if (mid) {
			u64 const off = src.page_offset + head;

			loaded = tidset_load(dms, tid_set,
					     rx_tracker->sbuf_cursor + packed_bytes,
					     src.dma_pages + off / PAGE_SIZE,
					     off & (PAGE_SIZE - 1), mid);
			packed_bytes += loaded;
			placed_bytes += loaded;
			cursor += loaded;
			remaining -= loaded;
			if (loaded < mid)
				break;
			tidset_load_pad(dms, tid_set);
		}

		if (tail) {
			if (!tidset_load_edge(dms, tid_set,
					      rx_tracker->sbuf_cursor + packed_bytes,
					      cursor, tail))
				break;
			packed_bytes += tail;
			placed_bytes += sizeof(u64);
			cursor += tail;
			remaining -= tail;
		}
	}

	/* An empty tidset always takes the first fragment. */
	if (WARN_ON_ONCE(!packed_bytes))
		return -EINVAL;

	tidset_load_complete(dms, tid_set);
	rc = &dms->read_request_chunks[tid_set];
	rc->cycle_real_bytes = packed_bytes;

	*tid_info = rc->chunk[0].tid_info;
	/* Quadwords placed, bounce edges' pad included. */
	read_size_qw = placed_bytes >> 3;

	read_req_state = &dms->read_requests[tid_set];
	gen = read_req_state->generation + 1;
	spec_charged = read_req_state->spec_charged;
	/*
	 * Every field not named here (drain state, perf) starts at 0.
	 * spec_charged carries over: a speculative tidset re-armed for the
	 * transfer's next request still owes its budget unit, returned at FREE.
	 */
	*read_req_state = (struct hfi2_dms_read_request_state){
		.total_requested_qws = read_size_qw,
		.remaining_qws = read_size_qw,
		.rx_tracker = rx_tracker,
		.tid_set = tid_set,
		.state = HFI2_DMS_TIDSET_STATE_ENABLED,
		.stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS),
		.generation = gen,
		.has_bounce = rc->scatter_count != 0,
		.saved_size_qw = read_size_qw,
		.saved_port_idx = rx_tracker->hdr.port_idx,
		.saved_remote_lid = rx_tracker->hdr.remote_lid,
		.saved_remote_rift_key = rx_tracker->hdr.remote_rift_key,
		.saved_entropy = rx_tracker->hdr.entropy,
		/*
		 * Bounce edges complete only once this side copies them out, so
		 * the source must not release a chained child on egress.
		 */
		.flags = rc->scatter_count ? HFI2_DMS_DR_FLAG_UNALIGNED : 0,
		.spec_charged = spec_charged,
	};

	if (rc->scatter_count) {
		rc->scatter_generation = gen;
		rc->scatter_valid = true;
	}

	*tidset_nbytes = packed_bytes;
	return 0;
}

/*
 * One chunk with one gather element covering it, whose length is the
 * request's placed bytes, is fully described by the BTH size_qw plus the
 * range's sbuf_offset/tid_info: such a request is sent in compact form.
 */
static bool _request_is_compact(struct hfi2_dms_read_request_chunks const *rc,
				u32 read_size_qw)
{
	return rc->load_nchunks == 1 && rc->load_ngather == 1 &&
	       hfi2_dms_recv_chunk_count(&rc->chunk[0]) == 1 &&
	       hfi2_dms_recv_chunk_length(&rc->chunk[0]) == rc->gather[0].length &&
	       rc->gather[0].length == (read_size_qw << 3);
}

/*
 * Build a ready-to-send DATA_REQUEST frame carrying @rc's recv_chunks and
 * gather elements into @cmd and return its length in quadwords (including the
 * PBC). @cmd must be large enough for the frame (dms->pio_scratch).
 */
static u32 hfi2_dms_cmd_data_request_stage(struct hfi2_dms *dms,
					   union _pkt_cmd *cmd, u8 port_idx,
					   struct hfi2_dms_read_request_chunks const *rc,
					   hfi2_dms_rift_key_t tx_rift_key,
					   hfi2_dms_rift_key_t rx_rift_key,
					   u32 src_lid, u32 read_size_qw,
					   u16 generation, u16 entropy,
					   u64 order_key, u8 flags,
					   enum hfi2_dms_msg_type msg_type)
{
	u8 *dst = (u8 *)cmd +
		_msgtype_pio_payload_offset[HFI2_DMS_MSG_TYPE_DATA_REQUEST];
	u32 const chunks_bytes =
		rc->load_nchunks * sizeof(struct hfi2_dms_recv_chunk);
	u32 const arrays_bytes =
		_data_request_arrays_bytes(rc->load_nchunks, rc->load_ngather);
	bool const compact = _request_is_compact(rc, read_size_qw);
	u32 wire_bytes;
	u32 pkt_len_qws;

	cmd->pio = dms->protocol_cmd_templates[port_idx][msg_type];

	cmd->data_request.tx_rift_key = tx_rift_key;
	cmd->data_request.rx_rift_key = rx_rift_key;
	memset(cmd->data_request.reserved2, 0,
	       sizeof(cmd->data_request.reserved2));
	cmd->data_request.flags = flags;
	cmd->data_request.generation = generation;

	if (compact) {
		cmd->data_request.sbuf_offset = rc->gather[0].sbuf_offset;
		cmd->data_request.tid_info = rc->chunk[0].tid_info;
		cmd->data_request.recv_chunk_count = 0;
		wire_bytes = 0;
		goto staged;
	}

	cmd->data_request.gather_count = rc->load_ngather;
	memset(cmd->data_request.reserved0, 0,
	       sizeof(cmd->data_request.reserved0));
	cmd->data_request.tid_info = 0;
	cmd->data_request.recv_chunk_count = rc->load_nchunks;
	/*
	 * recv_chunks followed by gather elements. Arrays that fit the 120-byte
	 * control HDRQ inline budget go in the inline area. Larger ones go
	 * whole into the eager portion of the packet, which starts right after
	 * the inline area: zero the inline area and place both arrays after it,
	 * so the receiver finds them at the start of its eager buffer.
	 */
	if (arrays_bytes > HFI2_DMS_DR_INLINE_BYTES) {
		memset(dst, 0, HFI2_DMS_DR_INLINE_BYTES);
		dst += HFI2_DMS_DR_INLINE_BYTES;
		wire_bytes = HFI2_DMS_DR_INLINE_BYTES + arrays_bytes;
	} else {
		wire_bytes = arrays_bytes;
	}
	memcpy(dst, rc->chunk, chunks_bytes);
	memcpy(dst + chunks_bytes, rc->gather,
	       rc->load_ngather * sizeof(struct hfi2_dms_gather));

staged:
	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, src_lid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, src_lid);
	_dms_lane_sel_set(cmd->bth, src_lid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, _dms_route_control_for_order_key(order_key));
	_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
	cmd->bth[2] = (read_size_qw << 16) | (cmd->bth[2] & 0xffff);

	cmd->data_request.entropy = entropy;

	pkt_len_qws = _pkt_len_qws(HFI2_DMS_MSG_TYPE_DATA_REQUEST, wire_bytes);
	pkt_len_qws = _pkt_cmd_test_len_pad(cmd, pkt_len_qws);
	_pkt_cmd_set_lengths(cmd, pkt_len_qws);

	return pkt_len_qws;
}

/*
 *_inject_data_request - Inject a DATA_REQUEST (or DATA_REQUEST_REPLAY, via
 * msg_type) packet from a fully-initialized read_request_state. All
 * parameters needed to build the packet are read from
 * dms->read_requests[tid_set].saved_* fields. This is the single injection
 * point used by both the normal path and the DRAINING re-inject path.
 */
static int _inject_data_request(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_msg_type msg_type)
{
	struct hfi2_dms_read_request_state *read_req_state = &dms->read_requests[tid_set];
	struct hfi2_dms_read_request_chunks const *rc = &dms->read_request_chunks[tid_set];
	union _pkt_cmd *cmd = (union _pkt_cmd *)dms->pio_scratch;

	/* The request's counts size the frame staged in pio_scratch. */
	if (WARN_ON_ONCE(rc->load_nchunks == 0 ||
			 rc->load_nchunks > HFI2_DMS_DR_MAX_CHUNKS ||
			 rc->load_ngather < rc->load_nchunks ||
			 rc->load_ngather > HFI2_DMS_DR_MAX_GATHER))
		return -EINVAL;

	hfi2_dms_cmd_data_request_stage(dms, cmd,
					read_req_state->saved_port_idx,
					rc,
					read_req_state->saved_remote_rift_key,
					read_req_state->rx_tracker->hdr.local_rift_key,
					read_req_state->saved_remote_lid,
					read_req_state->saved_size_qw,
					read_req_state->generation,
					read_req_state->saved_entropy,
					read_req_state->rx_tracker->hdr.order_key,
					read_req_state->flags, msg_type);

	return _inject_cmd_pio(dms, &cmd->pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

static int _inject_data_request_replay(struct hfi2_dms *dms, u32 tid_set)
{
	return _inject_data_request(dms, tid_set, HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY);
}

int hfi2_dms_impl_make_data_request(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, u32 tid_set)
{
	u64 start;
	u64 nbytes_to_request;
	u32 tid_info;
	int ret;
	u64 end;

	dms_trace(dms_make_data_request, dms, rx_tracker, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(rx_tracker == NULL);

	start = dms_rdtsc();

#if HFI2_DMS_COUNTERS_ENABLE
	ktime_t begin = ktime_get();
#endif
	/* Entropy drives the SDMA-engine hash + LRH. A chained child pins to its
	 * inherited engine (rides behind parent via FIFO); everything else rotates.
	 */
	if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		if (rx_tracker->chain_inherit_valid)
			rx_tracker->hdr.entropy = rx_tracker->chain_inherit_entropy;
		else
			rx_tracker->hdr.entropy = _dms_entropy_next(dms);
	}

	ret = _tidset_enable(dms, tid_set, rx_tracker, &tid_info, &nbytes_to_request);
	if (ret < 0) {
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
		return ret;
	}
#if HFI2_DMS_COUNTERS_ENABLE
	dms->read_requests[tid_set].perf.begin = begin;
	dms->read_requests[tid_set].perf.tidset_enabled = ktime_get();
#endif

	ret = _inject_data_request(dms, tid_set, HFI2_DMS_MSG_TYPE_DATA_REQUEST);
	if (ret < 0) {
		dd_dev_dbg(dms->dd, "Unable to send data request.\n");
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
		return ret;
	}

	rx_tracker->sbuf_cursor += nbytes_to_request;

	_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * HFI2_DMS_STALE_BACKOFF_BASE_MS);

	end = dms_rdtsc();
	dms->counters.make_data_request += end - start;

	return 0;
}

/* Issue-path narrow-to-one arm. Call AFTER tidsets_in_use is updated so the
 * count is current. Signals a parked child only.
 */
static void _chain_signal_final_data_request(struct hfi2_dms *dms,
					     struct hfi2_dms_rx_tracker *parent_rx)
{
	union hfi2_dms_tracker *parent = (union hfi2_dms_tracker *)parent_rx;
	struct hfi2_dms_transfer_handle const parent_h = _tracker_to_handle(parent);
	struct hfi2_dms_transfer_handle const child_h = parent->hdr.child_handle;
	union hfi2_dms_tracker *child;
	int ret;

	if (child_h.value == 0)
		return;

	child = _handle_to_tracker(child_h);
	if (!child) {
		dms->counters.chain_null_handle++;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (child->hdr.parent_handle.value != parent_h.value) {
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	/* Narrow-to-one fast path is DATA_START-only. */
	if (child->hdr.chain_park_at !=
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START)
		return;

	/*
	 * Not while a bounce-edge tidset is in flight: its edges are copied
	 * out after the child's same-engine data could land. A later tidset
	 * completion retries; parent completion releases the child otherwise.
	 */
	if (_rx_tracker_inflight_has_bounce(dms, parent_rx))
		return;

	/* Claim the release exactly once. */
	parent->hdr.chain_signalled = true;

	/* Inherit the parent's narrowed entropy. */
	if (parent_rx->tidsets_in_use > 0) {
		u64 const bitmap = parent_rx->tidsets_inflight_bitmap;
		u16 *const entropy = &child->rx.chain_inherit_entropy;

		child->rx.chain_inherit_valid =
			_dms_read_requests_inflight_entropy_narrowed(dms, bitmap, entropy);
	}

	if (child->hdr.health_state !=
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) {
		child->hdr.chain_child_released = true;
		return;
	}

	child->hdr.chain_child_released = true;

	/* Sever the link; the child copies out its own bounce edges at tidset completion. */
	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;

	/* Burst only: child inherits this engine, rides behind the parent via FIFO. */
	ret = _chain_resume_read_at_data_start(dms, &child->rx);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
		return;
	}
	dms->counters.chain_released_read_at_data_start++;
}

static void _chain_signal_last_engine(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker)
{
	if (!(rx_tracker->sbuf_cursor >= rx_tracker->total_payload &&
	      rx_tracker->tidsets_in_use <= 1))
		return;

	if (!rx_tracker->hdr.chain_signalled &&
	    rx_tracker->hdr.child_handle.value != 0)
		_chain_signal_final_data_request(dms, rx_tracker);
}

int calculate_access_mr_page_offset(struct hfi2_dms *dms,
					 struct hfi2_dms_access *access,
					 u64 offset, u32 size, u64 *page_offset)
{
	struct hfi2_dms_mr *rbuf;
	u64 relative_offset;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(!page_offset);

	rbuf = access->page_provider.provider_ctx;
	DMS_BUG_ON(!rbuf);

	/*
	 * The protocol-supplied `offset` is interpreted by MR mode: in
	 * VADDR mode it is an absolute user virtual address; in OFFSET
	 * mode it is a byte offset relative to the start of the access
	 * subrange. Normalize to `relative_offset` (bytes into the access)
	 * so the subrange bounds check is expressed in a single coordinate
	 * system regardless of mode.
	 */
	if (rbuf->mode == HFI2_DMS_MR_MODE_VADDR) {
		u64 const access_vaddr_start = rbuf->user.addr + access->offset;

		if (offset < access_vaddr_start) {
			dd_dev_info(dms->dd,
				    "%s: VADDR offset %llx below access start %llx\n",
				    __func__, offset, access_vaddr_start);
			return -EINVAL;
		}
		relative_offset = offset - access_vaddr_start;
	} else {
		relative_offset = offset;
	}

	if (relative_offset > access->size ||
	    size > (access->size - relative_offset)) {
		dd_dev_info(dms->dd,
			    "%s: Invalid access range offset %llx rel %llx size %x (access size %llx mode %d)\n",
			    __func__, offset, relative_offset, size,
			    access->size, rbuf->mode);
		return -EINVAL;
	}

	/*
	 * Delegate the MR-local page-offset translation and final
	 * bounds-check against the extended (page-aligned) MR length to
	 * calculate_mr_page_offset(). It interprets its `offset`
	 * argument per mr->mode, so pass the input offset unchanged in
	 * VADDR mode and (access->offset + relative_offset) in OFFSET
	 * mode.
	 */
	if (rbuf->mode == HFI2_DMS_MR_MODE_VADDR)
		return calculate_mr_page_offset(dms, rbuf, offset, size,
						page_offset);

	return calculate_mr_page_offset(dms, rbuf,
					access->offset + relative_offset,
					size, page_offset);
}

int calculate_mr_page_offset(struct hfi2_dms *dms, struct hfi2_dms_mr * mr, u64 offset, u32 size, u64 *page_offset)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);
	DMS_BUG_ON(!page_offset);

	if (mr->mode == HFI2_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < mr->user.addr) {
			dd_dev_info(dms->dd, "Invalid virtual address offset.\n");
			return -EINVAL;
		}
		*page_offset = mr->region_offset + offset - mr->user.addr;
	} else {
		*page_offset = mr->region_offset + offset;
	}

	if ((*page_offset + size) > mr->extended_vaddr.len) {
		dd_dev_info(dms->dd,
			    "%s: Invalid length from offset %llx + %x > %lx\n",
			    __func__, *page_offset, size,
			    mr->extended_vaddr.len);
		return -EINVAL;
	}

	return 0;
}

static bool
_read_start_spec_requests_valid(struct hfi2_dms_read_start_parameters const *p)
{
	if (p->tid_count > HFI2_DMS_READ_START_SPECULATIVE_TID_MAX)
		return false;
	for (u8 i = 0; i < p->tid_count; i++) {
		struct hfi2_dms_spec_request const *r = &p->spec[i];

		if (!r->recv_chunk_count ||
		    r->recv_chunk_count > HFI2_DMS_DR_MAX_CHUNKS ||
		    r->gather_count < r->recv_chunk_count ||
		    r->gather_count > HFI2_DMS_DR_MAX_GATHER)
			return false;
	}
	return true;
}

int hfi2_dms_impl_handle_read_start(struct hfi2_dms *dms,
		struct hfi2_dms_read_start_metadata const *metadata,
		struct hfi2_dms_read_start_parameters const *parameters,
		void const *arrays)
{
	u64 start;
	struct hfi2_dms_client_state * client = NULL;
	struct hfi2_dms_access *access;
	struct hfi2_dms_page_provider *page_provider;
	struct hfi2_dms_tx_tracker *tx_tracker;
	int ret = 0;
	u64 end;
	u64 page_offset = 0;
	enum hfi2_dms_err_type reason = HFI2_DMS_ERR_TYPE_NONE;

	DMS_BUG_ON(dms == NULL);

	if (parameters->tbytes == 0) {
		reason = HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION;
		goto nack;
	}

	/*
	 * A speculative READ_START's request counts are peer-supplied and size
	 * the arrays walked when serving it; bound them as a DATA_REQUEST's are.
	 */
	if (metadata->speculative &&
	    !_read_start_spec_requests_valid(parameters)) {
		reason = HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION;
		goto nack;
	}

	start = dms_rdtsc();

	access = hfi2_dms_access_lookup(dms, parameters->dms_key, &client);
	if (!client) {
		reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		/*
		 * Diagnostic-only: report whether a matching registration
		 * command is still pending in the client's cmdq. Does not
		 * change dispatch below.
		 */
		if (client->diag_access_fn) {
			if (client->diag_access_fn(client->diag_access_ctx,
						   parameters->dms_key.access))
				dms->counters.access_deferred_pending_cmd_found++;
			else
				dms->counters.access_deferred_pending_cmd_not_found++;
		}
		return -EAGAIN;
	}

	page_provider = &access->page_provider;
	/* Bilateral promote: a remote rank is initiating an RDMA-READ
	 * whose source is one of THIS rank's MRs (identified by the
	 * access lookup above).  Complementary to the explicit
	 * user_mr_promote() at the initiator-side cmd-handler in
	 * bulksvc_user.c.  Idempotent.
	 */
	if (access->page_provider.promote)
		page_provider->promote(page_provider->provider_ctx);

	ret = calculate_access_mr_page_offset(dms, access, parameters->offset, parameters->tbytes, &page_offset);
	if (ret < 0) {
		reason = HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	union hfi2_dms_tracker *tracker = hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
			metadata->rx_rift_key, metadata->slid, parameters->order_key, HFI2_DMS_XFER_TYPE_TARGET, HFI2_DMS_XFER_OP_READ);
	if (!tracker) {
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}

	ret = access_xfer_begin(dms, access, metadata->slid, metadata->rx_rift_key, tracker);
	if (ret == HFI2_DMS_ACCESS_ALREADY_STARTED) {
		union hfi2_dms_tracker *live =
			_access_inflight_find(access, metadata->slid,
					      metadata->rx_rift_key);
		enum hfi2_dms_start_gen_rel rel =
			live ? _start_gen_compare(parameters->order_key,
						  live->hdr.order_key)
			     : HFI2_DMS_START_GEN_DUP;

		if (rel == HFI2_DMS_START_GEN_NEWER) {
			/*
			 * Newer generation: tear down the stale tracker and
			 * re-admit fresh.  In-line cancel is safe only for a
			 * PERSISTENT access -- the nested _dms_rift_poll drain
			 * cannot free it (never ACTIVE_TEARDOWN) and touches only
			 * waitlist-parked trackers, not our fresh one; access is
			 * re-looked-up by key below.  An ephemeral access would
			 * free on drain and need deferral.
			 */
			WARN_ON_ONCE(access->type != HFI2_DMS_ACCESS_TYPE_PERSISTENT);
			hfi2_dms_tx_tracker_cancel(dms, &live->tx, -ECANCELED);
			live = NULL; /* freed+recycled by cancel; guard future deref */
			access = hfi2_dms_access_lookup(dms, parameters->dms_key,
							&client);
			if (!client || !access) {
				hfi2_dms_impl_tracker_recycle(dms, tracker);
				reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
				goto nack;
			}
			ret = access_xfer_begin(dms, access, metadata->slid,
						metadata->rx_rift_key, tracker);
			if (ret < 0) {
				hfi2_dms_impl_tracker_recycle(dms, tracker);
				reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
				goto nack;
			}
		} else {
			/*
			 * Exact-generation duplicate (re-injected/wire dup) or a
			 * stale orphan of a prior generation. Discard the new
			 * tracker. A duplicate is the initiator re-driving; answer
			 * with DATA_START once the live tracker holds a real rift
			 * key. A KEY_NOT_SET tracker recovers via _dms_rift_poll();
			 * a stale orphan is dropped.
			 *
			 * A speculative initiator that falls back re-sends an
			 * ordinary READ_START; the DATA_START answers it too.
			 */
			hfi2_dms_impl_tracker_recycle(dms, tracker);
			/*
			 * A responder whose payload has all gone out waits in
			 * WAITING_FOR_REMOTE_ACK: re-sending DATA_START would
			 * move it back and refuse the ACK if it is only late,
			 * as on a NOT_FOUND STATUS response.
			 */
			if (rel == HFI2_DMS_START_GEN_DUP && live &&
			    !_rift_key_error(live->tx.hdr.local_rift_key) &&
			    live->tx.payload_remaining) {
				dms->counters.reinject_data_start++;
				ret = hfi2_dms_impl_inject_data_start(dms, &live->tx);
				if (ret < 0)
					hfi2_dms_tx_tracker_cancel(dms, &live->tx, ret);
			}
			return 0;
		}
	} else if (ret < 0) {
		hfi2_dms_impl_tracker_recycle(dms, tracker);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
	}

	tx_tracker = &tracker->tx;

	tx_tracker->op = HFI2_DMS_TX_TRACKER_OP_RDMA_READ;
	tx_tracker->read.access = access;
	tx_tracker->read.metadata = *metadata;
	tx_tracker->read.parameters = *parameters;

	/* Adopt the caller's policy (fast_fail + stale shift) from the START flags. */
	tx_tracker->hdr.fast_fail = hfi2_dms_start_flags_fast_fail(parameters->flags);
	tx_tracker->hdr.stale_backoff_shift =
		hfi2_dms_start_flags_stale_shift(parameters->flags);

	tx_tracker->total_payload = parameters->tbytes;
	tx_tracker->payload_remaining = parameters->tbytes;
	tx_tracker->xfer_start_byte_offset = page_offset;

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)tx_tracker);
	if (ret < 0) {
		access_xfer_end(dms, access, (union hfi2_dms_tracker *)tx_tracker,
				parameters->flags, parameters->imm_data,
				parameters->order_key, ret);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	if (ret > 0) {
		u8 const generation = tx_tracker->hdr.generation;

		tx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
		ret = _dms_tx_rift_continue_read_start(dms, tx_tracker, arrays);
		if (ret < 0) {
			/*
			 * A failing drive may already have cancelled the
			 * tracker (_sdma_inject -EMSGSIZE); cancel released the
			 * key, ended the access and recycled the tracker, so
			 * only the NACK remains to be sent.
			 */
			if (tx_tracker->hdr.generation == generation) {
				union hfi2_dms_tracker *t = (union hfi2_dms_tracker *)tx_tracker;

				_rift_release(&dms->rift, tx_tracker->hdr.local_rift_key);
				access_xfer_end(dms, access, t, parameters->flags,
						parameters->imm_data, parameters->order_key,
						-ENOMEM);
				hfi2_dms_impl_tracker_recycle(dms, t);
			}
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
	}

	end = dms_rdtsc();
	dms->counters.handle_data_request += end - start;

	return 0;

nack:
	dd_dev_warn_ratelimited(dms->dd, "DMS_DIAG: READ_START NACK reason=%s dms_key=%llu slid=%u tbytes=%u offset=%llu\n",
		    _nack_reason_str(reason), parameters->dms_key.value,
		    metadata->slid, parameters->tbytes, parameters->offset);
	_nack_log(dms, reason, parameters->dms_key);
	/*
	 * Echo the message type the initiator sent so its NACK handler, which
	 * matches on the NACK's message-type field, locates the pending tracker
	 * regardless of which READ variant it issued.
	 */
	_inject_nack(dms,
		     metadata->speculative ? HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE
					   : HFI2_DMS_MSG_TYPE_READ_START,
		     reason, metadata->port_idx, metadata->slid, metadata->rx_rift_key);
	return 0;
}

static void hfi2_dms_impl_handle_read_start_packet(struct hfi2_dms *dms, u8 rcv_port,
						   union hfi2_dms_16b_header *hdr,
						   void *ebuf, bool speculative)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;

	struct hfi2_dms_read_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.rx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.size_qw = (u16) ((hdr->bth[2]) & 0xFFFF),
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.port_idx = rcv_port,
		.speculative = speculative,
		.entropy = hfi2_dms_lrh16B_entropy_get((u32 *)&hdr->lrh[0]),
	};

	/*
	 * A speculative READ_START's requests' arrays follow its body: inline when
	 * they fit the control HDRQ header, otherwise whole at the start of the
	 * eager buffer, exactly as a DATA_REQUEST's.
	 */
	void const *arrays = !speculative || !entry->read_start.tid_count ?
		NULL : ebuf ? ebuf : (void const *)(&entry->read_start + 1);

	/*
	 * The request counts are the peer's: the frame must carry the arrays
	 * they describe, where they describe them (counts themselves are
	 * bounded in hfi2_dms_impl_handle_read_start()).
	 */
	if (arrays) {
		struct hfi2_dms_spec_request const *r = entry->read_start.spec;
		u32 arrays_bytes = 0;
		bool in_eager;

		for (u8 i = 0; i < entry->read_start.tid_count &&
		     i < HFI2_DMS_READ_START_SPECULATIVE_TID_MAX; i++)
			arrays_bytes += _data_request_arrays_bytes(r[i].recv_chunk_count,
								   r[i].gather_count);
		in_eager = arrays_bytes > HFI2_DMS_RS_INLINE_BYTES;
		if (unlikely(in_eager != !!ebuf ||
			     !_request_arrays_fit(hfi2_dms_lrh16B_pkt_len_get(hdr->lrh),
						  offsetof(struct _hdrq_entry, read_start) +
						  sizeof_field(struct _hdrq_entry, read_start),
						  HFI2_DMS_RS_INLINE_BYTES,
						  arrays_bytes))) {
			dms->counters.health_invalid_data_request++;
			return;
		}
	}

	/*
	 * A deferred READ_START keeps only its body: a speculative one whose
	 * request needed arrays is then answered with DATA_START.
	 */
	int ret = hfi2_dms_impl_handle_read_start(dms, &metadata, &entry->read_start,
						  arrays);
	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_READ, &metadata, &entry->read_start);
}

static void _dms_write_signal_early_release(struct hfi2_dms *dms,
						struct hfi2_dms_tx_tracker *tx_tracker,
						u16 early_release_entropy)
{
	/* parent is this tx_tracker, re-fetched as a union tracker for the
	 * handle/health-state operations below.
	 */
	union hfi2_dms_tracker *const parent =
		_rift_lookup(&dms->rift, tx_tracker->hdr.local_rift_key);
	union hfi2_dms_tracker *child;
	int ret;

	/* A SEND is fully fenced: it releases its child only at completion. */
	if (_tx_tracker_is_send(tx_tracker))
		return;

	if (!parent || parent->hdr.chain_signalled ||
	    parent->hdr.child_handle.value == 0)
		return;

	child = _handle_to_tracker(parent->hdr.child_handle);
	if (!child ||
	    child->hdr.op != HFI2_DMS_XFER_OP_WRITE ||
	    child->hdr.parent_handle.value != _tracker_to_handle(parent).value ||
	    child->hdr.health_state !=
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY)
		return;

	/* A SEND child is fully fenced: it resumes only at parent completion. */
	if (_tx_tracker_is_send(&child->tx))
		return;

	parent->hdr.chain_signalled = true;
	child->hdr.chain_child_released = true;
	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	child->tx.write.chain_inherit_entropy = early_release_entropy;
	child->tx.write.chain_inherit_valid = true;
	_tracker_health_state_set(dms, child,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
					       HFI2_DMS_MSG_TYPE_WRITE_START,
					       false);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
	} else {
		dms->counters.chain_released_write_start_early++;
	}
}

static int
hfi2_dms_impl_handle_data_request(struct hfi2_dms *dms,
				  struct hfi2_dms_data_request_metadata const *metadata,
				  struct hfi2_dms_data_request_parameters const *parameters,
				  struct hfi2_dms_recv_chunk const *chunks,
				  u8 nchunks,
				  struct hfi2_dms_gather const *gather,
				  u8 ngather)
{
	struct hfi2_dms_tx_tracker *tx_tracker;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(parameters == NULL);

	hfi2_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;

	/*
	 * KEY_NOT_SET: a re-request of a speculative READ's tidset enabled
	 * before this responder was known; found by identity below.
	 */
	if (unlikely(_rift_key_error(tx_rift_key) &&
		     _rift_key_error(tx_rift_key) != HFI2_DMS_RIFT_ERR_KEY_NOT_SET)) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop DATA_REQUEST with error rift key 0x%04hx\n",
			   tx_rift_key.value);
		return 0;
	}

	tx_tracker = _rift_key_error(tx_rift_key) ? NULL :
		(struct hfi2_dms_tx_tracker *)_rift_lookup(&dms->rift, tx_rift_key);
	if (unlikely(!tx_tracker)) {
		/*
		 * Fast-path miss: the learned tx_rift_key generation has gone
		 * stale (the shared rift pool recycled the slot under QP churn,
		 * or a retried/duplicate DATA_REQUEST raced tracker progress).
		 * Recover by the stable transfer identity the initiator stamped
		 * in rx_rift_key -- the same (remote_rift_key, slid) identity the
		 * STATUS_REQUEST handler keys on, which is generation-independent.
		 *
		 * Accept a live READ tracker in either WAITING_FOR_REMOTE_DATA_REQUEST
		 * (1st tidset) or WAITING_FOR_REMOTE_ACK (2nd+ tidset of a segmented
		 * READ -- _sdma_inject() advances health to WAITING_FOR_REMOTE_ACK
		 * after the first tidset is injected, so every later DATA_REQUEST in
		 * a multi-tidset transfer legitimately arrives against a tracker
		 * already in that state). Terminal states (complete/cancel) release
		 * the rift key and NULL the slot in _rift_release(), so _rift_search
		 * can never return a completing/cancelling tracker here -- no state
		 * check for that case is needed.
		 *
		 * WRITE is intentionally excluded: the lazy-pull source read and
		 * early-release/chain-signal on payload_remaining==0 make a WRITE
		 * recovery unsafe without its own drained-buffer guard. WRITE
		 * stale-key DATA_REQUESTs continue to hard drop below.
		 */
		union hfi2_dms_tracker *recovered = NULL;

		if (parameters->rx_rift_key.value &&
		    !_rift_key_error(parameters->rx_rift_key))
			recovered = _rift_search(&dms->rift,
						 parameters->rx_rift_key,
						 metadata->slid);

		if (recovered &&
		    (recovered->hdr.health_state ==
			     HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST ||
		     recovered->hdr.health_state ==
			     HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) &&
		    recovered->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
			tx_tracker = &recovered->tx;
			dms->counters.diag_target_data_req_identity_recover++;
			if (recovered->hdr.health_state ==
			    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK)
				dms->counters.diag_target_data_req_identity_recover_waiting_ack++;
		} else {
			dms->counters.health_invalid_rift_key++;
			dms->counters.diag_target_data_req_rift_miss++;
			dd_dev_dbg_ratelimited(dms->dd,
					       "DMS_DIAG: target_req drop=rift_miss key=%05u rxk=%05u size_qw=%u\n",
					       tx_rift_key.value,
					       parameters->rx_rift_key.value,
					       metadata->size_qw);
			return 0;
		}
	}

	/*
	 * A request without a responder key is a re-request of a speculative
	 * tidset whose DATA_SPECULATIVE never reached the initiator: answer with
	 * DATA_SPECULATIVE so its DATA still promotes the tidset.
	 */
	_tx_serve_tidset_request(dms, tx_tracker, metadata->rx_id,
				 parameters->generation, parameters->entropy,
				 parameters->flags,
				 _rift_key_error(tx_rift_key) ?
					HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE :
				 metadata->is_replay ? HFI2_DMS_MSG_TYPE_DATA_REPLAY :
					HFI2_DMS_MSG_TYPE_DATA,
				 chunks, nchunks, gather, ngather);
	return 0;
}

/*
 * True if a peer-supplied recv_chunk and its @count gather elements describe
 * source bytes this transfer may send, and a landing area that stays inside
 * one tidset: every element non-empty and within [0, @total_payload), the
 * chunk's length their sum, its start offset inside one TID page, and its
 * quadword-padded bytes ending within the tidset that holds its first TID.
 */
static bool _tx_request_chunk_valid(struct hfi2_dms_recv_chunk const *chunk,
				    struct hfi2_dms_gather const *g, u8 count,
				    u32 total_payload)
{
	u32 const tid_info = chunk->tid_info;
	u64 const tid_offset = (tid_info & 0x7fff) << 2;
	u64 const tid_in_set = ((tid_info >> 16) & 0x3ff) &
			       (HFI2_DMS_TID_SET_SIZE - 1);
	u64 sum = 0;
	u64 padded = 0;

	for (u8 i = 0; i < count; i++) {
		if (!g[i].length || g[i].sbuf_offset >= total_payload ||
		    g[i].length > total_payload - g[i].sbuf_offset)
			return false;
		sum += g[i].length;
		padded += round_up(g[i].length, 8);
	}
	if (sum != hfi2_dms_recv_chunk_length(chunk))
		return false;

	return tid_offset < PAGE_SIZE &&
	       tid_in_set * HFI2_DMS_MAX_PAYLOAD_SIZE + tid_offset + padded <=
			HFI2_DMS_TID_SET_BYTES_MAX;
}

/*
 * Send the DATA one tidset request asks for: each recv_chunk's gather elements,
 * in order, into that chunk's TID range, as @data_msg_type. Shared by
 * DATA_REQUEST and by the requests a READ_START_SPECULATIVE carries.
 */
static void _tx_serve_tidset_request(struct hfi2_dms *dms,
				     struct hfi2_dms_tx_tracker *tx_tracker,
				     u8 rx_id, u16 generation, u16 entropy,
				     u8 flags, enum hfi2_dms_msg_type data_msg_type,
				     struct hfi2_dms_recv_chunk const *chunks,
				     u8 nchunks,
				     struct hfi2_dms_gather const *gather,
				     u8 ngather)
{
	struct hfi2_dms_sdma_req req;
	u8 next_gather = 0;

	DMS_BUG_ON((tx_tracker->op != HFI2_DMS_TX_TRACKER_OP_RDMA_READ) && (tx_tracker->op != HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE));

	/* DATA_REQUEST arrival is liveness: reset the stale cadence so the
	 * stale-sweep never cancels a transfer the peer is actively requesting.
	 */
	_tracker_note_peer_activity(dms, (union hfi2_dms_tracker *)tx_tracker);

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    (flags & HFI2_DMS_DR_FLAG_UNALIGNED))
		tx_tracker->write.unaligned = true;
	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    data_msg_type == HFI2_DMS_MSG_TYPE_DATA_REPLAY)
		tx_tracker->write.replayed = true;

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    tx_tracker->write.is_single_engine &&
	    !tx_tracker->write.chain_inherit_valid) {
		tx_tracker->write.chain_inherit_entropy = _dms_entropy_next(dms);
		tx_tracker->write.chain_inherit_valid = true;
	}

	u16 inject_entropy;

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ)
		inject_entropy = entropy;
	else if (tx_tracker->write.chain_inherit_valid)
		inject_entropy = tx_tracker->write.chain_inherit_entropy;
	else
		inject_entropy = _dms_entropy_next(dms);
	/*
	 * The byte odometer is advanced where the engine actually accepts the
	 * payload for egress (in _sdma_inject_req / the waitlist poll), not here:
	 * a DATA_REQUEST whose payload fails injection is parked on the SDMA
	 * waitlist under egress backpressure and must not count as progress.
	 *
	 * Use the tracker's live key, not the wire tx_rift_key: on the
	 * identity-recovery path the wire key is generation-stale and would
	 * mis-address SDMA completion.
	 */
	/*
	 * Copy the request's chunks and the gather elements they consume; the
	 * copy into req.gather[] is the one place a peer-supplied count indexes
	 * local memory, so bound each chunk's count to both a chunk's list and
	 * what remains of the received array. A malformed chunk ends the
	 * request there, sending the chunks before it.
	 *
	 * The elements themselves are the peer's too. Each must be non-empty
	 * (an empty one sends nothing, and a request of only empty ones would
	 * build an empty SDMA submission) and lie within this transfer's
	 * source -- pinning and the provider's runs are bounded by the whole
	 * buffer, not by the transfer the peer was granted. A chunk's length
	 * must be its elements' sum, as the initiator builds it.
	 */
	req = (struct hfi2_dms_sdma_req){
		.local_rift_key = tx_tracker->hdr.local_rift_key,
		.rx_id = rx_id,
		.generation = generation,
		.entropy = inject_entropy,
		.msg_type = data_msg_type,
		.page_offset = tx_tracker->xfer_start_byte_offset,
	};
	for (u8 i = 0; i < nchunks && i < HFI2_DMS_DR_MAX_CHUNKS; i++) {
		struct hfi2_dms_recv_chunk const *chunk = &chunks[i];
		u8 const count = hfi2_dms_recv_chunk_count(chunk);

		if (unlikely(!count || count > HFI2_DMS_DR_CHUNK_MAX_GATHER ||
			     count > ngather - next_gather ||
			     !_tx_request_chunk_valid(chunk, &gather[next_gather],
						      count, tx_tracker->total_payload))) {
			dms->counters.health_invalid_data_request++;
			break;
		}
		req.chunk[req.nchunks++] = *chunk;
		memcpy(&req.gather[next_gather], &gather[next_gather],
		       count * sizeof(*gather));
		next_gather += count;
		req.nbytes += hfi2_dms_recv_chunk_length(chunk);
	}
	req.ngather = next_gather;

	if (req.nchunks) {
		_sdma_inject_req(dms, &req);
		/* The inject may have cancelled the transfer (and freed it). */
		if (_rift_lookup(&dms->rift, req.local_rift_key) !=
		    (union hfi2_dms_tracker *)tx_tracker)
			return;
	}

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    !tx_tracker->write.unaligned &&
	    !tx_tracker->write.replayed &&
	    tx_tracker->payload_remaining == 0)
		_dms_write_signal_early_release(dms, tx_tracker, inject_entropy);
}

static int hfi2_dms_impl_handle_data_request_packet(struct hfi2_dms *dms,
						    union hfi2_dms_16b_header *hdr, void *ebuf)
{
	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;
	struct hfi2_dms_data_request_parameters const *parameters =
		&entry->data_request;
	u8 const nchunks = parameters->recv_chunk_count;
	struct hfi2_dms_recv_chunk const *recv_chunks;
	struct hfi2_dms_recv_chunk compact_chunk;
	struct hfi2_dms_gather compact_gather;

	struct hfi2_dms_data_request_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.size_qw = hfi2_dms_impl_data_request_size_qw_get(hdr),
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.is_replay = hfi2_dms_impl_message_type_get(hdr) ==
			HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY,
	};

	/* Compact form: one range, its length from the BTH size_qw. */
	if (!nchunks) {
		u32 const length = metadata.size_qw << 3;

		compact_chunk = (struct hfi2_dms_recv_chunk){
			.tid_info = parameters->tid_info,
			.length_count =
				FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, length) |
				FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, 1),
		};
		compact_gather = (struct hfi2_dms_gather){
			.sbuf_offset = parameters->sbuf_offset,
			.length = length,
		};
		return hfi2_dms_impl_handle_data_request(dms, &metadata,
							 parameters,
							 &compact_chunk, 1,
							 &compact_gather, 1);
	}

	/* Bounds the gather array walked below and the arrays' extent. */
	if (unlikely(nchunks > HFI2_DMS_DR_MAX_CHUNKS ||
		     parameters->gather_count > HFI2_DMS_DR_MAX_GATHER)) {
		dms->counters.health_invalid_data_request++;
		return 0;
	}

	/*
	 * The sender places both arrays inline when they fit the 120-byte HDRQ
	 * inline budget and otherwise whole at the start of the eager portion,
	 * which is exactly when the hardware hands over an eager buffer. The
	 * counts are the peer's: the frame must actually carry what they claim,
	 * where they claim it.
	 */
	{
		u32 const arrays_bytes =
			_data_request_arrays_bytes(nchunks, parameters->gather_count);
		bool const in_eager = arrays_bytes > HFI2_DMS_DR_INLINE_BYTES;

		if (unlikely(parameters->gather_count < nchunks ||
			     in_eager != !!ebuf ||
			     !_request_arrays_fit(hfi2_dms_lrh16B_pkt_len_get(hdr->lrh),
						  offsetof(struct _hdrq_entry, data_request) +
						  offsetof(struct hfi2_dms_data_request_parameters,
							   arrays),
						  HFI2_DMS_DR_INLINE_BYTES,
						  arrays_bytes))) {
			dms->counters.health_invalid_data_request++;
			return 0;
		}
	}
	recv_chunks = ebuf ? ebuf :
		(struct hfi2_dms_recv_chunk const *)parameters->arrays;

	return hfi2_dms_impl_handle_data_request(dms, &metadata, parameters,
						 recv_chunks, nchunks,
						 (struct hfi2_dms_gather const *)
						 &recv_chunks[nchunks],
						 parameters->gather_count);
}

void hfi2_dms_impl_handle_ack(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr, enum hfi2_dms_msg_type const type)
{
	union hfi2_dms_proto_pkt_ack * ack;
	struct hfi2_dms_tx_tracker *tx_tracker;

	DMS_WARN_ON(dms == NULL);
	DMS_WARN_ON(hdr == NULL);
	DMS_WARN_ON(hfi2_dms_impl_message_type_get(hdr) != type);

	ack = (union hfi2_dms_proto_pkt_ack *)hdr;

	if (type == HFI2_DMS_MSG_TYPE_ACK) {
		hfi2_dms_rift_key_t const tx_rift_key = ack->info.tx_rift_key;

		if (unlikely(_rift_key_error(tx_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop ACK with error rift key 0x%04hx\n",
				   tx_rift_key.value);
			return;
		}

		tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, tx_rift_key);
		if (!tx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
			return;
		}

		/*
		 * Guard against stale ACK completing the wrong tracker.
		 */
		if (tx_tracker->hdr.health_state != HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) {
			dd_dev_dbg(dms->dd,
				"ACK rejected: tx rift key 0x%04hx (%hu %hu) tracker in state %d, expected WAITING_FOR_REMOTE_ACK\n",
				tx_rift_key.value,
				_rift_key_generation(tx_rift_key),
				_rift_key_index(tx_rift_key),
				tx_tracker->hdr.health_state);
			return;
		}
		hfi2_dms_handle_tx_tracker_completion(dms, tx_rift_key, ack->info.flags);
	}
}

int hfi2_dms_impl_handle_write_start(struct hfi2_dms *dms, struct hfi2_dms_write_start_metadata const *metadata,
		struct hfi2_dms_write_start_parameters const *parameters, void *hbuf, void *ebuf, u32 const eager_nbytes)
{
	int ret;
	struct hfi2_dms_access *access;
	struct hfi2_dms_page_provider *page_provider;
	struct hfi2_dms_client_state *client;
	u64 byte_offset_from_first_mr_page;
	struct hfi2_dms_rx_tracker *rx_tracker;

	DMS_BUG_ON(dms == NULL);
	enum hfi2_dms_err_type reason = HFI2_DMS_ERR_TYPE_NONE;

	/* An externally-resolved-destination WRITE_START carries no access
	 * key; the registered upper layer resolves the landing buffer (DMS
	 * stays destination-agnostic), then the payload lands via the WRITE
	 * landing plane.
	 */
	if (metadata->flags & HFI2_DMS_WRITE_START_FLAG_EXT_DEST) {
		struct hfi2_dms_page_provider ext_provider;
		u64 ext_rbuf_start_offset = 0;
		void *ext_cmpl_ctx = NULL;
		enum hfi2_dms_ext_dest_status dst;

		if (!dms->ext_dest.resolve) {
			reason = HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}

		dst = dms->ext_dest.resolve(dms,
				parameters->dms_key, parameters->imm_data,
				parameters->order_key,
				metadata->flags, parameters->xfer_size,
				&ext_provider, &ext_rbuf_start_offset,
				&ext_cmpl_ctx);
		switch (dst) {
		case HFI2_DMS_EXT_DEST_OK:
			break;
		case HFI2_DMS_EXT_DEST_ALREADY_DELIVERED: {
			union hfi2_dms_proto_cmd_ack cmd =
				hfi2_dms_proto_cmd_ack_make(dms,
					metadata->port_idx, metadata->slid,
					metadata->tx_rift_key, 0, 0);
			dms->counters.health_send_replay_reack++;
			_inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
					HFI2_DMS_TRANSFER_HANDLE_NONE, false);
			return 0;
		}
		case HFI2_DMS_EXT_DEST_RNR:
			reason = HFI2_DMS_ERR_TYPE_RNR;
			goto nack;
		case HFI2_DMS_EXT_DEST_NOMEM:
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		case HFI2_DMS_EXT_DEST_CONSUMED:
		case HFI2_DMS_EXT_DEST_DROP:
		default:
			reason = HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}

		union hfi2_dms_tracker *ext_tracker =
			hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
				metadata->tx_rift_key, metadata->slid,
				parameters->order_key,
				HFI2_DMS_XFER_TYPE_TARGET,
				HFI2_DMS_XFER_OP_WRITE);
		if (!ext_tracker) {
			dms->ext_dest.complete(dms, ext_cmpl_ctx, -ENOMEM);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		rx_tracker = &ext_tracker->rx;
		rx_tracker->op = HFI2_DMS_RX_TRACKER_OP_EXT_DEST;
		rx_tracker->tidsets_in_use = 0;
		rx_tracker->tidsets_inflight_bitmap = 0;
		rx_tracker->chain_inherit_entropy = 0;
		rx_tracker->chain_inherit_valid = false;
		rx_tracker->write.metadata = *metadata;
		rx_tracker->write.parameters = *parameters;
		rx_tracker->write.access = NULL;
		rx_tracker->write.ext_cmpl_ctx = ext_cmpl_ctx;

		rx_tracker->total_payload = parameters->xfer_size;
		rx_tracker->payload_remaining = parameters->xfer_size;
		rx_tracker->sbuf_cursor = 0;
		rx_tracker->sbuf_start_offset = 0;
		rx_tracker->rbuf_start_offset = ext_rbuf_start_offset;
		rx_tracker->page_provider = ext_provider;

		ret = _rift_allocate(&dms->rift, ext_tracker);
		if (ret < 0) {
			dms->ext_dest.complete(dms, ext_cmpl_ctx, ret);
			rx_tracker->write.ext_cmpl_ctx = NULL;
			hfi2_dms_impl_tracker_recycle(dms, ext_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		if (ret > 0) {
			rx_tracker->hdr.local_rift_number =
				dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
			ret = _dms_rx_rift_continue_write_start(dms, rx_tracker,
					hbuf, ebuf, eager_nbytes);
			if (ret < 0) {
				_rift_release(&dms->rift,
					      rx_tracker->hdr.local_rift_key);
				dms->ext_dest.complete(dms, ext_cmpl_ctx,
						       -ENOMEM);
				rx_tracker->write.ext_cmpl_ctx = NULL;
				hfi2_dms_impl_tracker_recycle(dms,
					(union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
				goto nack;
			}
		}
		return 0;
	}

	access = hfi2_dms_access_lookup(dms, parameters->dms_key, &client);
	if (!client) {
		dd_dev_info(dms->dd, "WRITE_START: client not found key=%llx\n",
			    parameters->dms_key.value);
		reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		/*
		 * Diagnostic-only: report whether a matching registration
		 * command is still pending in the client's cmdq. Does not
		 * change dispatch below.
		 */
		if (client->diag_access_fn) {
			if (client->diag_access_fn(client->diag_access_ctx,
						   parameters->dms_key.access))
				dms->counters.access_deferred_pending_cmd_found++;
			else
				dms->counters.access_deferred_pending_cmd_not_found++;
		}
		return -EAGAIN;
	}

	page_provider = &access->page_provider;
	/* Bilateral promote: a remote rank is initiating an RDMA-WRITE
	 * whose destination is one of THIS rank's MRs (identified by
	 * the access lookup above).  Complementary to the explicit
	 * user_mr_promote() at the initiator-side cmd-handler in
	 * bulksvc_user.c.  Idempotent.
	 */
	if (access->page_provider.promote)
		page_provider->promote(page_provider->provider_ctx);

	ret = calculate_access_mr_page_offset(dms, access, parameters->offset, parameters->xfer_size, &byte_offset_from_first_mr_page);
	if (ret < 0) {
		struct hfi2_dms_mr const *acc_mr =
			access->page_provider.provider_ctx;

		dd_dev_info(dms->dd, "WRITE_START: range violation offset=%llx size=%u pp.len=%llu pp.region_offset=%llu acc.off=%llu acc.sz=%llu\n",
			    parameters->offset, parameters->xfer_size,
			    access->page_provider.length,
			    acc_mr ? acc_mr->region_offset : 0,
			    access->offset, access->size);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	union hfi2_dms_tracker *tracker = hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
			metadata->tx_rift_key, metadata->slid, parameters->order_key, HFI2_DMS_XFER_TYPE_TARGET, HFI2_DMS_XFER_OP_WRITE);
	if (!tracker) {
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	rx_tracker = &tracker->rx;
	rx_tracker->op = HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE;
	rx_tracker->tidsets_in_use = 0;
	rx_tracker->tidsets_inflight_bitmap = 0;
	rx_tracker->chain_inherit_entropy = 0;
	rx_tracker->chain_inherit_valid = false;
	rx_tracker->write.metadata = *metadata;
	rx_tracker->write.parameters = *parameters;
	rx_tracker->write.ext_cmpl_ctx = NULL;

	/* Adopt the caller's policy (fast_fail + stale shift) from the START flags. */
	rx_tracker->hdr.fast_fail = hfi2_dms_start_flags_fast_fail(metadata->flags);
	rx_tracker->hdr.stale_backoff_shift =
		hfi2_dms_start_flags_stale_shift(metadata->flags);

	rx_tracker->total_payload = parameters->xfer_size;
	rx_tracker->payload_remaining = parameters->xfer_size;
	rx_tracker->sbuf_cursor = 0;
	rx_tracker->sbuf_start_offset = 0;

	rx_tracker->rbuf_start_offset = byte_offset_from_first_mr_page;
	rx_tracker->page_provider = access->page_provider;

	rx_tracker->write.access = access;

	ret = access_xfer_begin(dms, access, metadata->slid, metadata->tx_rift_key,
				tracker);
	if (ret == HFI2_DMS_ACCESS_ALREADY_STARTED) {
		/*
		 * A live transfer shares this (slid, tx_rift_key).  Classify by
		 * generation (order_key[31:24]):
		 *
		 *  - NEWER: the initiator fast-failed the prior attempt and
		 *    re-issued this WRITE_START.  Tear down the stale target
		 *    tracker (frees its rift key / tidsets, may free an
		 *    ephemeral access), re-look up the access, and re-admit this
		 *    fresh generation.
		 *  - DUP/STALE: a true duplicate or a stale orphan.  Drop it --
		 *    re-issuing WRITE_START here would bypass the tidset DRAINING
		 *    fence that owns lost-DATA_REQUEST recovery and risk
		 *    mis-delivery.  A same-generation body mismatch can only be a
		 *    corrupted/spoofed packet; drop (do not NACK, which would map
		 *    to -EBUSY and cancel the healthy live transfer) and log.
		 */
		union hfi2_dms_tracker *live =
			_access_inflight_find(access, metadata->slid,
					      metadata->tx_rift_key);
		enum hfi2_dms_start_gen_rel rel =
			live ? _start_gen_compare(parameters->order_key,
						  live->hdr.order_key)
			     : HFI2_DMS_START_GEN_DUP;

		if (rel == HFI2_DMS_START_GEN_NEWER) {
			/*
			 * Newer generation: tear down + re-admit fresh.  In-line
			 * cancel safe only for a PERSISTENT access (see the READ
			 * path); access is re-looked-up by key below.
			 */
			WARN_ON_ONCE(access->type != HFI2_DMS_ACCESS_TYPE_PERSISTENT);
			hfi2_dms_rx_tracker_cancel(dms, &live->rx, -ECANCELED);
			live = NULL; /* freed+recycled by cancel; guard future deref */
			access = hfi2_dms_access_lookup(dms, parameters->dms_key,
							&client);
			if (!client || !access) {
				rx_tracker->write.access = NULL;
				hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
				goto nack;
			}
			rx_tracker->write.access = access;
			rx_tracker->page_provider = access->page_provider;
			ret = access_xfer_begin(dms, access, metadata->slid,
						metadata->tx_rift_key, tracker);
			if (ret < 0) {
				rx_tracker->write.access = NULL;
				hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
				goto nack;
			}
		} else {
			/*
			 * DUP (same generation) or STALE (older generation).  Only
			 * a same-generation DUP can be a genuine body mismatch; a
			 * STALE replay legitimately differs in order_key and is
			 * simply dropped, so it must NOT be flagged as a mismatch.
			 */
			struct hfi2_dms_write_start_parameters const *lp =
				(rel == HFI2_DMS_START_GEN_DUP && live)
					? &live->rx.write.parameters : NULL;

			rx_tracker->write.access = NULL;
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);

			if (rel == HFI2_DMS_START_GEN_DUP &&
			    !(lp &&
			      lp->dms_key.value == parameters->dms_key.value &&
			      lp->offset == parameters->offset &&
			      lp->xfer_size == parameters->xfer_size &&
			      lp->order_key == parameters->order_key)) {
				dms->counters.write_start_dup_mismatch++;
				dd_dev_warn_ratelimited(dms->dd,
							"DMS_DIAG: WRITE_START dup mismatch slid=%u tx_rift_key=%u; dropping (not cancelling live transfer)\n",
					metadata->slid, metadata->tx_rift_key.value);
			}
			return 0;
		}
	} else if (ret < 0) {
		rx_tracker->write.access = NULL;
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
	}

	/*
	 * eager-only WRITE: the whole payload is in this packet, so the
	 * target copies it, ACKs, releases the access and recycles the tracker
	 * without a target rift key.
	 */
	if (hbuf && parameters->xfer_size <= eager_nbytes) {
		rx_tracker->hdr.local_rift_key =
			_rift_key_create_err(HFI2_DMS_RIFT_ERR_KEYLESS);
		dms->counters.eager_rx_keyless++;
		ret = _dms_rx_rift_continue_write_start(dms, rx_tracker, hbuf, ebuf, eager_nbytes);
		if (ret < 0) {
			access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker,
					metadata->flags, parameters->imm_data,
					parameters->order_key, -ENOMEM);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		return 0;
	}

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)rx_tracker);
	if (ret < 0) {
		access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker,
				metadata->flags, parameters->imm_data,
				parameters->order_key, ret);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	if (ret > 0) {
		rx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
		ret = _dms_rx_rift_continue_write_start(dms, rx_tracker, hbuf, ebuf, eager_nbytes);
		if (ret < 0) {
			_rift_release(&dms->rift, rx_tracker->hdr.local_rift_key);
			access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker, metadata->flags, parameters->imm_data, parameters->order_key, -ENOMEM);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
	}

	return 0;

nack:
	dd_dev_warn_ratelimited(dms->dd, "DMS_DIAG: WRITE_START NACK reason=%s dms_key=%llu slid=%u size=%u offset=%llu\n",
		    _nack_reason_str(reason), parameters->dms_key.value,
		    metadata->slid, parameters->xfer_size, parameters->offset);
	_nack_log(dms, reason, parameters->dms_key);
	_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START, reason, metadata->port_idx, metadata->slid, metadata->tx_rift_key);
	return 0;
}

static void hfi2_dms_handle_data_start_packet(struct hfi2_dms *dms, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	u32 const hdr_qws =
		(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START_EAGER] - 8) >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	u32 eager_nbytes = 0;

	if (eager) {
		eager_nbytes = _dms_data_start_eager_nbytes_get(hdr->bth);
		if (unlikely(pktlen_qws < hdr_qws + 1 ||
			     eager_nbytes > ((pktlen_qws - hdr_qws - 1) << 3))) {
			dms->counters.health_short_packet_drop++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: short DATA_START_EAGER pktlen_qws=%u hdr_qws=%u eager_nbytes=%u dropped\n",
				pktlen_qws, hdr_qws, eager_nbytes);
			return;
		}
	}

	hfi2_dms_handle_data_start(dms, hdr, eager, ebuf, eager_nbytes);
}

static void hfi2_dms_impl_handle_write_start_packet(struct hfi2_dms *dms, u8 rcv_port, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;

	/*
	 * WRITE_START_EAGER carries no payload in the header queue: the whole
	 * payload is in the eager buffer at WSE_EBUF_PAYLOAD_OFFSET.  @hbuf is
	 * the eager payload pointer for eager packets and NULL otherwise, so
	 * the receive path takes the normal TID/SDMA flow for non-eager.
	 */
	void *hbuf = (eager && ebuf) ? (u8 *)ebuf + WSE_EBUF_PAYLOAD_OFFSET : NULL;

	u32 const hdr_qws = WSE_WIRE_PAYLOAD_OFFSET >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	u32 eager_nbytes = 0;

	if (eager) {
		eager_nbytes = entry->write_start.eager_nbytes;
		if (unlikely(pktlen_qws < hdr_qws + 1 || !ebuf ||
			     eager_nbytes > ((pktlen_qws - hdr_qws - 1) << 3))) {
			dms->counters.health_short_packet_drop++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: short WRITE_START_EAGER pktlen_qws=%u hdr_qws=%u eager_nbytes=%u dropped\n",
				pktlen_qws, hdr_qws, eager_nbytes);
			return;
		}
	}

	struct hfi2_dms_write_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.tx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.flags = (u16) ((hdr->bth[2]) & 0xFFFF),
		.port_idx = rcv_port
	};

	int ret = hfi2_dms_impl_handle_write_start(dms, &metadata, &entry->write_start, hbuf, ebuf, eager_nbytes);

	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_WRITE, &metadata, &entry->write_start);
}

/*
 * WRITE_START_TINY: the payload follows the write_start parameters in the
 * header queue, in place of the reserved_qw and eager_payload slots, and is
 * landed from there like a WRITE_START_EAGER payload.  A path that cannot use
 * the in-packet payload (a deferred retry) requests it with DATA_REQUESTs,
 * as for any WRITE_START.
 */
static void hfi2_dms_impl_handle_write_start_tiny_packet(struct hfi2_dms *dms,
							 u8 rcv_port,
							 union hfi2_dms_16b_header *hdr)
{
	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;
	u8 *payload = (u8 *)entry + WST_PAYLOAD_OFFSET;
	u32 const hdr_qws = WST_PAYLOAD_OFFSET >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	struct hfi2_dms_write_start_parameters const *parameters =
		&entry->write_start;
	u32 nbytes;
	int ret;

	if (unlikely(pktlen_qws < hdr_qws + 1 ||
		     pktlen_qws > hdr_qws + 1 + WST_PAYLOAD_MAX / 8))
		goto bad_len;

	nbytes = parameters->eager_nbytes;
	if (unlikely(nbytes > ((pktlen_qws - hdr_qws - 1) << 3) ||
		     parameters->xfer_size > nbytes))
		goto bad_len;

	struct hfi2_dms_write_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.tx_rift_key = {.value = (u16)((hdr->bth[2] >> 16) & 0xFFFF)},
		.flags = (u16)((hdr->bth[2]) & 0xFFFF),
		.port_idx = rcv_port
	};

	ret = hfi2_dms_impl_handle_write_start(dms, &metadata, parameters,
					       payload, NULL, nbytes);
	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_WRITE, &metadata,
				     parameters);
	return;

bad_len:
	dms->counters.health_short_packet_drop++;
	dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: bad WRITE_START_TINY pktlen_qws=%u xfer_size=%u dropped\n",
				pktlen_qws, entry->write_start.xfer_size);
}

void hfi2_dms_tx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_tx_tracker *tx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);
	DMS_BUG_ON(tx_tracker->hdr.side != HFI2_DMS_XFER_SIDE_TX);

	dms->counters.trackers_cancelled_tx++;

	/*
	 * BTS owns sibling/child cancellation (it flushes in-flight
	 * trackers by handle on the verbs path).  Here we only sever our own
	 * chain links so a parent's later signal cannot touch this recycled
	 * tracker; we do NOT cascade into parked children.
	 */
	_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)tx_tracker);
	tx_tracker->hdr.child_handle =
		HFI2_DMS_TRANSFER_HANDLE_NONE;

	hfi2_dms_rift_key_t const key = tx_tracker->hdr.local_rift_key;
	enum hfi2_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_KEY_DISABLED);

	if (status != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {

		/* Scan every waitlist bucket: entropy-hashed injects park on real
		 * engines 0..num_engines-1, not just IDX_ANY.
		 */
		for (s32 i = 0; i < HFI2_DMS_SDMA_ENGINE_IDX_COUNT; ++i) {
			enum hfi2_dms_sdma_engine_idx const idx = (enum hfi2_dms_sdma_engine_idx) i;
			struct hfi2_dms_sdma_tracker *waiter = _sdma_engine_waitlist_peek(dms, idx);
			while (waiter) {
				struct hfi2_dms_sdma_tracker *next = (struct hfi2_dms_sdma_tracker *) waiter->hdr.dlist.next;
				if ((struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, waiter->info.local_rift_key) == tx_tracker) {
					_sdma_engine_waitlist_remove(dms, idx, waiter);
					_sdma_tracker_free(dms, waiter);
				}
				waiter = next;
			}
		}

		_rift_release(&dms->rift, key);

	} else {
		enum hfi2_dms_xfer_type t = tx_tracker->hdr.type;
		enum hfi2_dms_xfer_side s = tx_tracker->hdr.side;
		hfi2_dms_impl_dlist_remove(&dms->rift.type[t].side[s].waitlist,
					   (struct hfi2_dms_dlist_element *)tx_tracker);
	}

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, (union hfi2_dms_tracker *)tx_tracker, tx_tracker->read.parameters.flags, tx_tracker->read.parameters.imm_data, tx_tracker->hdr.order_key, err);
		tx_tracker->read.access = NULL;

	} else if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, err);
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
	_dms_rift_poll_request(dms);
}

static void hfi2_dms_rx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->hdr.side != HFI2_DMS_XFER_SIDE_RX);

	dms->counters.trackers_cancelled_rx++;

	/*
	 * Do not return speculative budget here: the tidsets are DISABLED below
	 * and each returns its unit at its own FREE transition. Returning it now,
	 * while they are still DISABLED and not reprogrammable, would over-
	 * subscribe the pool.
	 */

	/*
	 * BTS owns sibling/child cancellation (it flushes in-flight
	 * trackers by handle on the verbs path).  Here we only sever our own
	 * chain links so a parent's later signal cannot touch this recycled
	 * tracker; we do NOT cascade into parked children.
	 */
	_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
	rx_tracker->hdr.child_handle =
		HFI2_DMS_TRANSFER_HANDLE_NONE;

	hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
	enum hfi2_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_KEY_DISABLED);
	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_NONE && !_rift_key_side_rx(key));

	if (status != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {

		_tidset_waiter_remove(dms, rx_tracker);

		u32 const sz = HFI2_DMS_ARRAY_SIZE(dms->read_requests);
		bool disabled_any = false;
		for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
			union hfi2_dms_tracker *tracker = (union hfi2_dms_tracker *) dms->read_requests[tid_set].rx_tracker;
			if (((struct hfi2_dms_rx_tracker *)tracker == rx_tracker) &&
					    (dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_ENABLED ||
					     dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_DRAINING)) {
				DMS_BUG_ON(rx_tracker->tidsets_in_use == 0);
				_dms_rx_tracker_tidset_inflight_clear(rx_tracker, tid_set);
				_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_DISABLED);
				disabled_any = true;
			}
		}
		if (disabled_any)
			flush_wc();

		_cancel_cache_add(dms, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, err);

		_rift_cancel(&dms->rift, key);

	} else {
		enum hfi2_dms_xfer_type t = rx_tracker->hdr.type;
		enum hfi2_dms_xfer_side s = rx_tracker->hdr.side;
		hfi2_dms_impl_dlist_remove(&dms->rift.type[t].side[s].waitlist,
					   (struct hfi2_dms_dlist_element *)rx_tracker);
	}

	if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, err);
	} else if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST) {
		dms->ext_dest.complete(dms,
			rx_tracker->write.ext_cmpl_ctx, err);
	} else { // HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access,
			(union hfi2_dms_tracker *)rx_tracker,
			rx_tracker->write.metadata.flags,
			rx_tracker->write.parameters.imm_data,
			rx_tracker->write.parameters.order_key,
			err);
		rx_tracker->write.access = NULL;
	}

	_dms_rift_poll_request(dms);
	_service_global_tidset_waiters(dms);

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
}

int hfi2_dms_cancel_tracker_by_handle(struct hfi2_dms *dms,
				      struct hfi2_dms_transfer_handle handle,
				      int err)
{
	union hfi2_dms_tracker *tracker;

	if (WARN_ON_ONCE(!dms))
		return -EFAULT;

	tracker = _handle_to_tracker(handle);
	if (unlikely(!tracker)) {
		dms->counters.cancel_by_handle_notfound++;
		return -ENOENT;
	}

	if (unlikely(tracker->hdr.chain_signalled)) {
		dms->counters.cancel_by_handle_chain_signalled++;
		return -ENOENT;
	}

	if (_rift_key_error(tracker->hdr.local_rift_key) == HFI2_DMS_RIFT_ERR_NONE &&
	    _rift_lookup(&dms->rift, tracker->hdr.local_rift_key) != tracker) {
		dms->counters.cancel_by_handle_notfound++;
		return -ENOENT;
	}

	_tracker_cancel(dms, tracker, err);
	dms->counters.cancel_by_handle_success++;

	return 0;
}


static void _tidset_waiter_enqueue(struct hfi2_dms *dms,
				      struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	WARN_ON_ONCE(rx_tracker->sbuf_cursor >= rx_tracker->total_payload);

	hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(key));
	DMS_BUG_ON(!_rift_key_side_rx(key));

	_rift_keyring_add(&dms->tidset_waiters, key);

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION);
}

static void _tidset_waiter_remove(struct hfi2_dms *dms,
				     struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	_rift_keyring_remove(&dms->tidset_waiters, rx_tracker->hdr.local_rift_key);
}

static void _service_global_tidset_waiters(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);

	while (!_rift_keyring_empty(&dms->tidset_waiters)) {
		hfi2_dms_rift_key_t const key = _rift_keyring_peek(&dms->tidset_waiters);
		union hfi2_dms_tracker *tracker = _rift_lookup(&dms->rift, key);

		if (!tracker) {
			_rift_keyring_advance(&dms->tidset_waiters);
			continue;
		}

		struct hfi2_dms_rx_tracker *rx_tracker = &tracker->rx;

		if (rx_tracker->sbuf_cursor >= rx_tracker->total_payload) {
			_rift_keyring_advance(&dms->tidset_waiters);
			continue;
		}

		u32 const free_count = _tidset_free_count(dms);
		if (free_count == 0)
			break;

		u32 tidset;
		int ret;
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);

		for (u32 i = 1; i < HFI2_DMS_TRACKER_TIDSET_MAX &&
		     rx_tracker->sbuf_cursor < rx_tracker->total_payload &&
		     free_count > i; i++) {
			_tidset_idx_peek(dms, &tidset);
			_tidset_idx_reserve(dms, tidset);
			ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
			if (ret != 0) {
				_tidset_idx_release(dms, tidset);
				break;
			}
			DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
			_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
		}

		_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
						HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA);

		_chain_signal_last_engine(dms, rx_tracker);

		_rift_keyring_advance(&dms->tidset_waiters);
	}
}

static void _tracker_cancel(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, int err)
{
	DMS_BUG_ON(!tracker);

	switch (tracker->hdr.side) {
	case HFI2_DMS_XFER_SIDE_TX:
		hfi2_dms_tx_tracker_cancel(dms, &tracker->tx, err);
		break;
	case HFI2_DMS_XFER_SIDE_RX:
		hfi2_dms_rx_tracker_cancel(dms, &tracker->rx, err);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

void hfi2_dms_impl_handle_nack_packet(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_nack *nack;
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_rx_tracker *rx_tracker;

	DMS_WARN_ON(!dms);
	DMS_WARN_ON(!hdr);
	DMS_WARN_ON(hfi2_dms_impl_message_type_get(hdr) != HFI2_DMS_MSG_TYPE_NACK);

	nack = (union hfi2_dms_pkt_nack *)hdr;

	DMS_WARN_ON(nack->info.err_type == HFI2_DMS_ERR_TYPE_NONE);

	hfi2_dms_rift_key_t const nack_rift_key = nack->info.rift_key;

	if (unlikely(_rift_key_error(nack_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop NACK with error rift key 0x%04hx\n",
			   nack_rift_key.value);
		return;
	}

	int err = 0;
	switch (nack->info.err_type) {
	case HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND:
		err = -EINVAL;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND:
		err = -EINVAL;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION:
		err = -EACCES;
		break;
	case HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION:
		err = -EMSGSIZE;
		break;
	case HFI2_DMS_ERR_TYPE_NO_MEMORY:
		err = -ENOMEM;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_BUSY:
		err = -EBUSY;
		break;
	case HFI2_DMS_ERR_TYPE_RNR:
		err = -EINVAL;
		break;
	default:
		err = -EPROTO;
		break;
	}

	switch (nack->info.msg_type) {
	case HFI2_DMS_MSG_TYPE_WRITE_START:
		if (unlikely(!_rift_key_side_tx(nack_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop WRITE_START NACK with non-tx rift key 0x%04hx\n",
				   nack_rift_key.value);
			return;
		}
		tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, nack_rift_key);
		if (!tx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
			return;
		}
		if (nack->info.err_type == HFI2_DMS_ERR_TYPE_RNR) {
			/* FAST_FAIL is strict: an RNR NACK is a replay decision, so cancel instead of retrying, even the immediate local retry. */
			if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)tx_tracker))
				return;
			tx_tracker->hdr.rnr_retry_count++;
			dms->counters.rnr_nack_retries++;
			if (tx_tracker->hdr.rnr_retry_count <= HFI2_DMS_RNR_IMMEDIATE_RETRY_MAX) {
				_tracker_reinject_start(dms, (union hfi2_dms_tracker *)tx_tracker);
				return;
			}
			if (!tx_tracker->hdr.rnr_pending) {
				dms->counters.rnr_nack_deferred++;
				tx_tracker->hdr.rnr_pending = true;
			}
			return;
		}
		dd_dev_dbg(dms->dd, "DMS: WRITE_START fatal NACK err_type=%u err=%d rift=0x%04hx\n",
			    nack->info.err_type, err, nack_rift_key.value);
		hfi2_dms_tx_tracker_cancel(dms, tx_tracker, err);
		break;

	case HFI2_DMS_MSG_TYPE_READ_START:
	case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
	case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
		if (unlikely(!_rift_key_side_rx(nack_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop READ_START NACK with non-rx rift key 0x%04hx\n",
				   nack_rift_key.value);
			return;
		}
		rx_tracker = (struct hfi2_dms_rx_tracker *) _rift_lookup(&dms->rift, nack_rift_key);
		if (!rx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
			return;
		}
		if (nack->info.err_type == HFI2_DMS_ERR_TYPE_RNR) {
			/* FAST_FAIL is strict: an RNR NACK is a replay decision, so cancel instead of retrying, even the immediate local retry. */
			if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)rx_tracker))
				return;
			rx_tracker->hdr.rnr_retry_count++;
			dms->counters.rnr_nack_retries++;
			if (rx_tracker->hdr.rnr_retry_count <= HFI2_DMS_RNR_IMMEDIATE_RETRY_MAX) {
				_tracker_reinject_start(dms, (union hfi2_dms_tracker *)rx_tracker);
				return;
			}
			if (!rx_tracker->hdr.rnr_pending) {
				dms->counters.rnr_nack_deferred++;
				rx_tracker->hdr.rnr_pending = true;
			}
			return;
		}
		dd_dev_dbg(dms->dd, "DMS: READ_START fatal NACK err_type=%u err=%d rift=0x%04hx\n",
			    nack->info.err_type, err, nack_rift_key.value);
		hfi2_dms_rx_tracker_cancel(dms, rx_tracker, err);
		break;

	default:
		dd_dev_dbg(dms->dd, "Received NACK for unknown message type %u with rift index: %hu, error type: %u\n", nack->info.msg_type, nack->info.rift_key.value, nack->info.err_type);
		break;
	}
}

static union hfi2_dms_tracker *_locate_tracker(struct hfi2_dms *dms, struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const remote_rift_key, u32 const remote_lid, u8 const port_idx)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(_rift_key_error(remote_rift_key) != HFI2_DMS_RIFT_ERR_NONE);

	union hfi2_dms_tracker *tracker;

	tracker = _rift_search(rift, remote_rift_key, remote_lid);
	if (tracker) {
		return tracker;
	}

	struct hfi2_dms_dlist_element *waiter;
	enum hfi2_dms_xfer_type const t = _rift_key_type_opposite(remote_rift_key);

	for (enum hfi2_dms_xfer_side s = 0; s < HFI2_DMS_XFER_SIDE_COUNT; ++s) {
		waiter = rift->type[t].side[s].waitlist.head;
		while (waiter) {
			tracker = container_of(waiter, union hfi2_dms_tracker, hdr.dlist);
			if (tracker->hdr.remote_rift_key.value == remote_rift_key.value &&
			    tracker->hdr.remote_lid == remote_lid &&
			    tracker->hdr.port_idx == port_idx)
				return tracker;
			waiter = waiter->next;
		}
	}

	return NULL;
}

static void _handle_single_status_request(struct hfi2_dms *dms,
					  u8 rcv_port, u32 remote_lid,
					  hfi2_dms_rift_key_t requester_rift_key)
{
	union hfi2_dms_tracker *tracker;

	if (unlikely(_rift_key_error(requester_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop STATUS_REQUEST entry with error rift key 0x%04hx\n",
			   requester_rift_key.value);
		return;
	}

	tracker = _locate_tracker(dms, &dms->rift, requester_rift_key,
				  remote_lid, rcv_port);

	/* An incoming STATUS_REQUEST is the peer polling this transfer: proof it
	 * is still live. Reset the stale cadence so a transfer under active
	 * status polling is never cancelled by the stale-sweep.
	 *
	 * Not for a parked child: that would end its park exemption and let its
	 * own sweep cancel it.
	 */
	if (tracker && !_rx_tracker_is_parked_at_data_start(tracker))
		_tracker_note_peer_activity(dms, tracker);

	if (_rift_key_side_tx(requester_rift_key)) {
		/*
		 * Requester has a TX tracker asking about our local RX
		 * (target) side.
		 */
		if (tracker) {
			enum hfi2_dms_tracker_health_state const state =
				tracker->hdr.health_state;

			switch (state) {
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START:
			case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE: {
				enum hfi2_dms_status_type const parked =
					HFI2_DMS_STATUS_TYPE_RESPONSE_PARKED;

				_inject_status_response_no_tracker(dms, rcv_port,
								   remote_lid,
								   requester_rift_key,
								   parked);
				break;
			}
			default:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			}
		} else {
			struct hfi2_dms_cancel_cache_entry *cancel_entry =
				_cancel_cache_find(dms, remote_lid,
						   requester_rift_key);

			if (cancel_entry) {
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED);
				_cancel_cache_remove(dms, remote_lid,
						     requester_rift_key);
			} else if (_access_deferred_find(dms, requester_rift_key, remote_lid)) {
				/* START is deferred awaiting access registration — suppress retransmit */
				dms->counters.rnr_duplicate_start++;
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_ACCESS_PENDING);
			} else {
				/*
				 * No local RX tracker, no cancel-cache record,
				 * not access-deferred. tracker == NULL is
				 * ambiguous (never-started vs completed-and-
				 * freed); report only what we know and let the
				 * requester reconcile against its health_state.
				 */
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND);
			}
		}
	} else {
		/*
		 * Requester has an RX tracker asking about our local TX
		 * (initiator) side.
		 */
		if (tracker) {
			enum hfi2_dms_tracker_health_state const state =
				tracker->hdr.health_state;

			switch (state) {
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST:
				if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
					enum hfi2_dms_msg_type const t =
						HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY;

					if (_tracker_cancel_if_fast_fail(dms, tracker))
						break;
					hfi2_dms_impl_inject_write_start(dms, &tracker->tx, t,
									 false);
				} else if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
					hfi2_dms_impl_inject_data_start(dms,
									&tracker->tx);
				}
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			default:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			}
		} else {
			struct hfi2_dms_cancel_cache_entry *cancel_entry =
				_cancel_cache_find(dms, remote_lid,
						   requester_rift_key);

			if (cancel_entry) {
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED);
				_cancel_cache_remove(dms, remote_lid,
						     requester_rift_key);
			} else {
				/*
				 * No local TX tracker, no cancel-cache record.
				 * tracker == NULL is ambiguous (completed-and-
				 * freed vs a READ_START that never created a TX
				 * tracker); report only what we know and let the
				 * requester reconcile against its health_state.
				 */
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND);
			}
		}
	}
}

void hfi2_dms_impl_handle_status_request_packet(struct hfi2_dms *dms,
						 u8 rcv_port,
						 union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_status_request *pkt =
		(union hfi2_dms_pkt_status_request *)hdr;
	u32 const remote_lid = _dms_peer_get(hdr);
	u8 count = pkt->info.count;
	u8 i;

	DMS_BUG_ON(!dms);

	if (count > HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES)
		count = HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES;

	for (i = 0; i < count; i++)
		_handle_single_status_request(dms, rcv_port, remote_lid,
					      pkt->info.entries[i]);
}

/*
 * True if a STATUS response may complete this TX tracker in place of the
 * ACK it is waiting for: all its payload went out as DATA in answer to the
 * initiator's own DATA_REQUESTs, which proves the initiator held the RX side.
 * A speculative READ's responder sends DATA from the requests in the
 * READ_START, so having sent everything proves nothing about the initiator:
 * a lost ACK and a cancelled initiator look the same from here, and only a
 * real ACK completes it -- whether or not DATA_REQUESTs followed.
 */
static bool _tx_tracker_status_completable(struct hfi2_dms_tx_tracker const *tx)
{
	if (tx->payload_remaining)
		return false;
	return tx->op != HFI2_DMS_TX_TRACKER_OP_RDMA_READ ||
	       !tx->read.metadata.speculative;
}

/*
 * NOT_FOUND recovery for a tx tracker parked in WAITING_FOR_REMOTE_ACK.
 *
 * Optimistic completion is sound ONLY when all the payload left as separate
 * DATA packets, i.e. payload_remaining == 0. The tracker enters
 * WAITING_FOR_REMOTE_ACK when it hands a request to SDMA; payload_remaining
 * is debited as the engine accepts each request's DATA. Outside a speculative READ the TX
 * side only sources that DATA in response to a DATA_REQUEST -- so the peer
 * provably created an RX tracker (see _tx_tracker_status_completable()).
 * A NOT_FOUND then means the peer completed and freed it (its ACK was
 * lost), and completing is correct. This mirrors the existing
 * TRANSFER_COMPLETE + WAITING_FOR_REMOTE_ACK path and the stale-ACK guard
 * in the ACK handler.
 *
 * A transfer whose payload rides INLINE in the START packet (eager)
 * instead jumps straight to WAITING_FOR_REMOTE_ACK with
 * payload_remaining still == total_payload. There a NOT_FOUND means the
 * START -- and therefore the only copy of the data -- was lost; the peer
 * never received anything. Completing would silently report success for
 * data that never landed. Treat it like a lost START: re-inject with retry
 * accounting and age out to -ETIMEDOUT, never complete.
 */
static void _tx_tracker_not_found_waiting_ack(struct hfi2_dms *dms,
					      union hfi2_dms_tracker *tracker,
					      hfi2_dms_rift_key_t requester_rift_key)
{
	if (_tx_tracker_status_completable(&tracker->tx)) {
		hfi2_dms_handle_tx_tracker_completion(dms, requester_rift_key,
						      HFI2_DMS_FLAG_COMPLETION_VIA_STATUS);
		return;
	}

	_tracker_stale_rearm_keep_count(dms, tracker);
	if (_tracker_is_dead(tracker, dms->now))
		_tracker_cancel(dms, tracker, -ETIMEDOUT);
	/*
	 * A speculative READ that sent everything from its READ_START has
	 * nothing to re-drive, and re-sending DATA_START would leave
	 * WAITING_FOR_REMOTE_ACK and refuse the ACK if it is only late: keep
	 * waiting for the ACK, or age out.
	 */
	else if (tracker->tx.payload_remaining &&
		 !_tracker_cancel_if_fast_fail(dms, tracker))
		_tracker_reinject_start(dms, tracker);
}

void hfi2_dms_impl_handle_status_response_packet(struct hfi2_dms *dms, u8 rcv_port, union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_status *pkt = (union hfi2_dms_pkt_status *)hdr;
	hfi2_dms_rift_key_t const requester_rift_key = pkt->info.requester_rift_key;
	union hfi2_dms_tracker *tracker;

	DMS_BUG_ON(!dms);

	tracker = _rift_lookup(&dms->rift, requester_rift_key);

	switch (pkt->info.type) {
	case HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT:
	/* Note: ACCESS_PENDING aliases WAITING_RIFT (same wire value 5) */
		{
			dms->counters.health_status_rsp_waiting_rift++;
			if (tracker) {
				bool const made_progress =
					pkt->info.rift_global_assigned !=
					tracker->hdr.remote_status.last_known_rift_global_assigned;

				tracker->hdr.remote_status.last_known_rift_tracker_ticket =
					pkt->info.rift_tracker_ticket;
				tracker->hdr.remote_status.last_known_rift_global_assigned =
					pkt->info.rift_global_assigned;
				if (made_progress) {
					u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS * 10;
					tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
					tracker->hdr.status_req_count = 0;
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET:
		{
			dms->counters.health_status_rsp_waiting_tidset++;
			if (tracker) {
				bool const made_progress =
					pkt->info.tidset_progress !=
					tracker->hdr.remote_status.last_known_tidset_progress;

				tracker->hdr.remote_status.last_known_tidset_progress =
					pkt->info.tidset_progress;
				if (made_progress) {
					u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS * 10;
					tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
					tracker->hdr.status_req_count = 0;
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS:
		{
			dms->counters.health_status_rsp_in_progress++;
			if (tracker) {
				bool const made_progress =
					pkt->info.packet_progress !=
					tracker->hdr.remote_status.last_known_packet_progress;

				tracker->hdr.remote_status.last_known_packet_progress =
					pkt->info.packet_progress;
				if (made_progress) {
					_tracker_stale_set_remote(dms, tracker, HFI2_DMS_STALE_BACKOFF_BASE_MS);
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_TRANSFER_COMPLETE:
		{
			dms->counters.health_status_rsp_complete++;
			if (tracker) {
				if (_rift_key_side_tx(requester_rift_key)) {
					/*
					 * Requester is TX — remote RX reports complete.
					 * Complete only if all payload left as separate
					 * DATA packets (payload_remaining == 0). A TX whose
					 * payload rode inline in the (possibly lost) START
					 * still has payload_remaining == total; a
					 * legacy TRANSFER_COMPLETE from an old peer must not
					 * silently complete it. Mismatch is treated as
					 * transient and aged out, never falsely completed.
					 */
					if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK &&
					    _tx_tracker_status_completable(&tracker->tx))
						hfi2_dms_handle_tx_tracker_completion(dms, requester_rift_key, HFI2_DMS_FLAG_COMPLETION_VIA_STATUS);
					else if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) {
						dms->counters.health_status_rsp_complete_transient++;
						_tracker_stale_rearm_keep_count(dms, tracker);
					}
				} else {
					/* Requester is RX tracker — remote TX completed, complete local RX */
					if (tracker->rx.payload_remaining == 0) {
						hfi2_dms_rx_tracker_handle_completion(dms, &tracker->rx, 0, 0);
					} else {
					/*
					 * COMPLETE with RX payload outstanding shouldn't occur (responder no
					 * longer fabricates it); treat as transient and rearm WITHOUT resetting
					 * status_req_count, so a stuck tracker still ages out to -ETIMEDOUT.
					 */
					dms->counters.health_status_rsp_complete_transient++;
					_tracker_stale_rearm_keep_count(dms, tracker);
					}
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_NOT_STARTED:
		{
			if (tracker) {
				dms->counters.health_status_rsp_not_started++;
				if (_rift_key_side_tx(requester_rift_key)) {
					/*
					 * TX-side requester can be an RDMA_WRITE
					 * initiator (resend WRITE_START) or an
					 * RDMA_READ target (resend DATA_START).
					 * Dispatch by op; otherwise the wrong
					 * union arm is serialized onto the wire
					 * (e.g. a zero dms_key WRITE_START from
					 * a READ TX tracker).
					 */
					if (tracker->hdr.health_state !=
					    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST &&
					    tracker->hdr.health_state !=
					    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK)
						break;

					if (!_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
				} else {
					/* Requester is RX tracker — remote didn't get READ_START, re-inject */
					if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START &&
					    !_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND:
		{
			/*
			 * The responder knows nothing about this rift key (no
			 * tracker, no cancel record). Reconcile against our own
			 * health_state — the only place that disambiguates
			 * "peer finished and freed" from "START never landed".
			 * Never fatally cancel here.
			 */
			dms->counters.health_status_rsp_not_found++;
			if (!tracker)
				break; /* ACK race: both sides already done */

			/*
			 * A START that never lands (e.g. permanent packet loss)
			 * must not loop forever. Advance the retry-limit accounting
			 * on every NOT_FOUND that drives a re-injection and bail to
			 * a terminal -ETIMEDOUT once the retry budget is exhausted.
			 * _tracker_stale_rearm_keep_count() increments
			 * status_req_count and re-arms the backoff timer; if the
			 * tracker has exhausted its retries, cancel terminally
			 * instead of re-injecting. This preserves recovery for the
			 * common case (a re-injected START gets through within the
			 * budget) while guaranteeing termination when it never can.
			 */
			if (_rift_key_side_tx(requester_rift_key)) {
				switch (tracker->hdr.health_state) {
				case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST:
					_tracker_stale_rearm_keep_count(dms, tracker);
					if (_tracker_is_dead(tracker, dms->now))
						_tracker_cancel(dms, tracker, -ETIMEDOUT);
					else if (!_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
					break;
				case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK:
					_tx_tracker_not_found_waiting_ack(dms, tracker,
									  requester_rift_key);
					break;
				default:
					break;
				}
			} else if (tracker->hdr.health_state ==
				   HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION) {
				/*
				 * RX requester blocked on local tidsets. The local
				 * tidset path owns recovery and sets status_req_count to
				 * the stale-exempt value, so this transfer must not be
				 * subject to the retry-limit cancel check: a single late
				 * NOT_FOUND from its prior WAITING_FOR_REMOTE_DATA phase
				 * would otherwise push the count past the budget and
				 * cancel a recoverable transfer. Leave it for the tidset
				 * path to drive. Termination is bounded: the DRAINING
				 * path cancels the tracker after HFI2_DMS_STALE_BACKOFF_MAX_COUNT
				 * retries (see _hfi2_dms_poll_read_requests, DRAINING arm).
				 */
				dms->counters.health_status_rsp_not_found_tidset_wait++;
			} else {
				/*
				 * On NOT_FOUND, bump retry accounting and reinject; once the budget is
				 * spent, terminate with -ETIMEDOUT so a START that never lands cannot
				 * loop forever.
				 */
				_tracker_stale_rearm_keep_count(dms, tracker);
				if (_tracker_is_dead(tracker, dms->now))
					_tracker_cancel(dms, tracker, -ETIMEDOUT);
				else if (tracker->hdr.health_state ==
					 HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START &&
					 !_tracker_cancel_if_fast_fail(dms, tracker))
					_tracker_reinject_start(dms, tracker);
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED:
		{
			if (tracker) {
				dms->counters.health_status_rsp_cancelled++;
				if (_rift_key_side_tx(requester_rift_key))
					hfi2_dms_tx_tracker_cancel(dms, &tracker->tx, -ECANCELED);
				else
					hfi2_dms_rx_tracker_cancel(dms, &tracker->rx, -ECANCELED);
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_PARKED:
		{
			dms->counters.health_status_rsp_parked++;
			if (tracker && _rift_key_side_tx(requester_rift_key)) {
				_tracker_stale_set_remote(dms, tracker,
							  HFI2_DMS_STALE_BACKOFF_BASE_MS);
				tracker->hdr.last_progress_time = dms->now;
			}
			break;
		}

	default:
		dd_dev_warn(dms->dd, "Received status response with unknown type: %u\n", pkt->info.type);
		break;
	}
}

u32 hfi2_dms_impl_data_request_size_qw_get(union hfi2_dms_16b_header *hdr)
{
	u32 ret;

	DMS_BUG_ON(hdr == NULL);
	ret = (u32) ((hdr->bth[2] >> 16) & 0xFFFF);
	return ret;
}

void hfi2_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid)
{
	u64 newlrh;

	DMS_BUG_ON(lrh16bc == NULL);
	newlrh = (*lrh16bc & ~0xFFFFFFull) | (dlid & 0xFFFFFF);

	*lrh16bc = newlrh;
}

void hfi2_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws)
{
	DMS_BUG_ON(lrh16bc == NULL);

	/* Set the length in QWs in the LRH16BC */
	*lrh16bc = (*lrh16bc & ~(HFI2_DMS_LRH16BC_LEN_QW_MASK << HFI2_DMS_LRH16BC_LEN_QW_SHIFT)) | (
		((u64) (len_qws & HFI2_DMS_LRH16BC_LEN_QW_MASK) << HFI2_DMS_LRH16BC_LEN_QW_SHIFT));
}

void hfi2_dms_impl_lrh16bc_entropy_set(u64 *lrh16bc, u16 entropy)
{
	DMS_BUG_ON(!lrh16bc);

	/* Set the 16-bit entropy field in the LRH16BC (bits [47:32]) */
	*lrh16bc &= ~(HFI2_DMS_LRH16BC_ENTROPY_MASK << HFI2_DMS_LRH16BC_ENTROPY_SHIFT);
	*lrh16bc |= ((u64)entropy << HFI2_DMS_LRH16BC_ENTROPY_SHIFT);
}

static void hfi2_dms_impl_lrh16bc_rc_set(u64 *lrh16bc, u8 rc)
{
	if (WARN_ON_ONCE(!lrh16bc))
		return;

	/* Set the 3-bit Route Control field in the LRH16BC (bits [30:28]) */
	*lrh16bc &= ~(HFI2_DMS_LRH16BC_RC_MASK << HFI2_DMS_LRH16BC_RC_SHIFT);
	*lrh16bc |= ((u64)(rc & HFI2_DMS_LRH16BC_RC_MASK) << HFI2_DMS_LRH16BC_RC_SHIFT);
}

void hfi2_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the DLID in the PBC
	*pbc = (*pbc & ~(((u64) PBC_DLID_MASK << PBC_DLID_SHIFT))) |
	       ((u64) (dlid & PBC_DLID_MASK) << PBC_DLID_SHIFT);
}

static u8 _pbc_port_idx_get(u64 pbc)
{
	return (pbc >> PBC_PORT_IDX_SHIFT) & PBC_PORT_IDX_MASK;
}

static void hfi2_dms_impl_pbc_length_dws_set(u64 *pbc, u32 length_dws)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the length in DWords in the PBC
	*pbc = (*pbc & ~(((u64) PBC_LENGTH_DWS_MASK << PBC_LENGTH_DWS_SHIFT))) |
	       ((u64) (length_dws & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT);
}

u64 hfi2_dms_impl_pbc_length_dws_get(u64 pbc)
{
	return (pbc >> PBC_LENGTH_DWS_SHIFT) & PBC_LENGTH_DWS_MASK;
}

/*
	return the 16bc size including PBC in DWs of the data
	packet type we send given the current payload size
*/
static u32 hfi2_dms_impl_data_pktlen_dws_from_payload_dws(u32 payload_dws)
{
	u32 ret;

	/* 16B compressed header (with PBC) + payload + 2 dws for 16B tail flit */
	ret = sizeof(union hfi2_dms_proto_cmd_data) / sizeof(u32) + payload_dws + 2;
	return ret;
}

/*
 * Build the SDMA descriptors for ONE contiguous DMA run.  This is the pure
 * JKR/CYR descriptor logic; the run-iterating wrapper lives in
 * hfi2_dms_impl_fill_payload().
 */
static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_run_descriptors(struct sdma_desc *start_desc, u64 nbytes,
				   u64 sbuf_page_offset,
				   dma_addr_t const *run_dma, bool is_jkr)
{
	u64 PHYS_PAGE_SIZE = PAGE_SIZE;
	u64 offset;
	struct sdma_desc *desc;
	u64 chunk_align_bytes;
	u64 page_idx;
	dma_addr_t phys_addr;
	u64 bytes_until_page_end;
	u64 nbytes_256_chunks;
	u64 page_align_bytes;
	u64 page_count;
	u64 i;
	u64 phy_addr;
	u64 chunk_tail_bytes;
	u64 tail_bytes;

	DMS_BUG_ON(start_desc == NULL);
	DMS_BUG_ON(run_dma == NULL);
	DMS_BUG_ON((PHYS_PAGE_SIZE & (PHYS_PAGE_SIZE - 1)) != 0);
	DMS_BUG_ON(nbytes > HFI2_DMS_MAX_PAYLOAD_SIZE);

	offset = sbuf_page_offset;
	desc = start_desc;

	if (is_jkr) {
		/*
		 * JKR errata requires a single descriptor must not cross
		 * a 256 byte boundary unless it is a multiple of 256 bytes in size.
		 */
		chunk_align_bytes = min((HFI2_DMS_PAYLOAD_CHUNK_SIZE - (offset & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1))) & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1), nbytes);
		if (chunk_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], chunk_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += chunk_align_bytes;
			nbytes -= chunk_align_bytes;
		}

		// fill 256 chunks until end of current page (if 4096 page) or end of 256 chunks in this page
		bytes_until_page_end = (PHYS_PAGE_SIZE - (offset & (PHYS_PAGE_SIZE - 1))) & (PHYS_PAGE_SIZE - 1);
		nbytes_256_chunks = nbytes & ~(HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		page_align_bytes = min(bytes_until_page_end, nbytes_256_chunks);
		DMS_BUG_ON((page_align_bytes & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
		if (page_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], page_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += page_align_bytes;
			nbytes -= page_align_bytes;
		}

		// in reality this should be MAX 1, but it could be 0 if we are
		// given a huge page
		page_count = nbytes / PHYS_PAGE_SIZE;
		for (i = 0; i < page_count; ++i) {
			DMS_BUG_ON((offset & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
			page_idx = offset / PHYS_PAGE_SIZE;
			phy_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], PHYS_PAGE_SIZE);
			_sdma_qw_set_phy_addr(&desc->qw[0], phy_addr);
			desc += 1;

			offset += PHYS_PAGE_SIZE;
			nbytes -= PHYS_PAGE_SIZE;
		}

		// tail chunks
		chunk_tail_bytes = nbytes & ~(HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		if (chunk_tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], chunk_tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += chunk_tail_bytes;
			nbytes -= chunk_tail_bytes;
		}

		// finally, tail bytes
		tail_bytes = nbytes & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		if (tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += tail_bytes;
			nbytes -= tail_bytes;
		}
	} else {
		/* For CYR there is no need to follow the JKR errata for payload alignment */
		bytes_until_page_end = (PHYS_PAGE_SIZE - (offset & (PHYS_PAGE_SIZE - 1))) & (PHYS_PAGE_SIZE - 1);
		page_align_bytes = min(bytes_until_page_end, nbytes);
		if (page_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], page_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += page_align_bytes;
			nbytes -= page_align_bytes;
		}

		page_count = nbytes / PHYS_PAGE_SIZE;
		for (i = 0; i < page_count; ++i) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phy_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], PHYS_PAGE_SIZE);
			_sdma_qw_set_phy_addr(&desc->qw[0], phy_addr);
			desc += 1;

			offset += PHYS_PAGE_SIZE;
			nbytes -= PHYS_PAGE_SIZE;
		}

		tail_bytes = nbytes;
		if (tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += tail_bytes;
			nbytes -= tail_bytes;
		}
	}

	DMS_BUG_ON(nbytes != 0); // We should have consumed all bytes

	return (struct hfi2_dms_impl_fill_state){
		.cur_desc = desc,
		.page_offset = offset, // This is the total offset we filled
	};
}

/*
 * Fill @nbytes of one packet's payload, iterating contiguous DMA runs from
 * the source provider (next_src_run) and emitting descriptors per run via
 * hfi2_dms_impl_fill_run_descriptors().  src_provider is always present.
 */
static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_payload(struct hfi2_dms_impl_fill_state fill_state,
			   u64 nbytes, bool is_jkr)
{
	u64 packet_remaining = nbytes;
	dma_addr_t const *run_dma = NULL;
	u64 run_page_offset = 0;

	while (packet_remaining) {
		struct hfi2_dms_impl_fill_state run_state;
		u64 run_chunk;

		if (fill_state.run_bytes_remaining == 0) {
			struct hfi2_dms_run run;
			int ret = fill_state.src_provider->next_src_run(
				fill_state.src_provider,
				fill_state.src_byte_offset,
				packet_remaining, &run);
			if (ret < 0) {
				fill_state.err = ret;
				return fill_state;
			}
			run_dma = run.dma_pages;
			run_page_offset = run.page_offset;
			fill_state.run_bytes_remaining = run.run_bytes;
			fill_state.page_offset = run_page_offset;
		}

		run_chunk = min_t(u64, packet_remaining,
				  fill_state.run_bytes_remaining);

		run_state = hfi2_dms_impl_fill_run_descriptors(
			fill_state.cur_desc, run_chunk, fill_state.page_offset,
			run_dma, is_jkr);
		fill_state.cur_desc = run_state.cur_desc;
		fill_state.page_offset = run_state.page_offset;

		packet_remaining -= run_chunk;
		fill_state.src_byte_offset += run_chunk;
		fill_state.run_bytes_remaining -= run_chunk;
	}

	return fill_state;
}

/*
 * Cursor state for budgeted DATA-payload descriptor emission.  run_dma is
 * the page-array base for the current source run; it is not part of struct
 * hfi2_dms_impl_fill_state and is re-derived only when run_bytes_remaining
 * drains to 0, so any mid-run checkpoint must snapshot it explicitly.
 */
struct hfi2_dms_fill_cursor {
	struct sdma_desc tail_desc;
	struct sdma_desc *cur_desc;
	struct hfi2_dms_page_provider const *src_provider;
	u64 src_byte_offset;
	u64 run_bytes_remaining;
	u64 page_offset;
	dma_addr_t const *run_dma;
	/*
	 * Gather list being sent: element gather_idx has elem_remaining source
	 * bytes left, at src_byte_offset; src_base is what each element's
	 * sbuf_offset is relative to. pad_owed is the zero bytes still owed
	 * after the finished element, so every element ends on a quadword
	 * boundary. The list is exhausted when gather_idx == gather_count.
	 */
	struct hfi2_dms_gather const *gather;
	struct sdma_desc const *pad_desc;
	u64 src_base;
	/*
	 * Also the reach handed to next_src_run when (re)fetching a run: the
	 * rest of the element, so a single contiguous source MR is returned as
	 * ONE run that spans every DATA packet of the element. run_dma then
	 * stays the same dma_list base while page_offset accumulates, keeping
	 * the head of the DMA-address array L1-resident and collapsing the
	 * per-packet provider callback into one call per contiguous region.
	 * The emitted run-chunk is still budget-bounded below.
	 */
	u64 elem_remaining;
	u8 gather_count;
	u8 gather_idx;
	u8 pad_owed;
	int err;
};

/* Start the cursor on gather element @idx (< gather_count). */
static void hfi2_dms_fill_elem_start(struct hfi2_dms_fill_cursor *cur, u8 idx)
{
	cur->gather_idx = idx;
	cur->src_byte_offset = cur->src_base + cur->gather[idx].sbuf_offset;
	cur->elem_remaining = cur->gather[idx].length;
	cur->run_bytes_remaining = 0;
}

/* Move past the finished element; after the last one the list is exhausted. */
static void hfi2_dms_fill_elem_next(struct hfi2_dms_fill_cursor *cur)
{
	if (cur->gather_idx + 1 < cur->gather_count) {
		hfi2_dms_fill_elem_start(cur, cur->gather_idx + 1);
		return;
	}
	cur->gather_idx = cur->gather_count;
	cur->run_bytes_remaining = 0;
}

/*
 * Emit descriptors for at most @max_bytes of one contiguous source run,
 * fetching the next run when the current one drains.  Returns the byte
 * count actually emitted (one run-chunk); sets cur->err and returns 0 on a
 * source provider failure.
 */
static u64 hfi2_dms_fill_bounded_step(struct hfi2_dms_fill_cursor *cur,
				      u64 max_bytes, bool is_jkr)
{
	struct hfi2_dms_impl_fill_state run_state;
	u64 run_chunk;

	/* Callers bound their requests by the wire bytes of the list. */
	if (WARN_ON_ONCE(cur->gather_idx >= cur->gather_count)) {
		cur->err = -EINVAL;
		return 0;
	}

	/*
	 * The pad ends on the quadword boundary the element started from, and
	 * every caller's bound is a quadword boundary at or past it, so it is
	 * always emitted whole.
	 */
	if (cur->pad_owed) {
		u8 const pad = cur->pad_owed;

		if (WARN_ON_ONCE(pad >= sizeof(u64) || max_bytes < pad)) {
			cur->err = -EINVAL;
			return 0;
		}
		*cur->cur_desc = cur->pad_desc[pad - 1];
		cur->cur_desc += 1;
		cur->pad_owed = 0;
		hfi2_dms_fill_elem_next(cur);
		return pad;
	}

	if (cur->run_bytes_remaining == 0) {
		struct hfi2_dms_run run;
		int ret = cur->src_provider->next_src_run(cur->src_provider,
							  cur->src_byte_offset,
							  cur->elem_remaining,
							  &run);
		if (ret < 0) {
			cur->err = ret;
			return 0;
		}
		/*
		 * A provider that returns success with a zero-length run makes
		 * no forward progress; the callers' "while (filled < cap)" loops
		 * would spin forever on the single-threaded BTS event thread,
		 * wedging all DMS on the device. Reject it as a provider
		 * contract violation.
		 */
		if (WARN_ON_ONCE(run.run_bytes == 0)) {
			cur->err = -EINVAL;
			return 0;
		}
		cur->run_dma = run.dma_pages;
		cur->page_offset = run.page_offset;
		cur->run_bytes_remaining = run.run_bytes;
	}

	run_chunk = min3(max_bytes, cur->run_bytes_remaining,
			 cur->elem_remaining);

	run_state = hfi2_dms_impl_fill_run_descriptors(cur->cur_desc, run_chunk,
						       cur->page_offset,
						       cur->run_dma, is_jkr);
	cur->cur_desc = run_state.cur_desc;
	cur->page_offset = run_state.page_offset;
	cur->src_byte_offset += run_chunk;
	cur->run_bytes_remaining -= run_chunk;
	cur->elem_remaining -= run_chunk;

	/* Element done: owe its quadword pad, or move straight on. */
	if (cur->elem_remaining == 0) {
		cur->pad_owed = -cur->gather[cur->gather_idx].length & 7;
		if (!cur->pad_owed)
			hfi2_dms_fill_elem_next(cur);
	}

	return run_chunk;
}

/*
 * Step the current run forward in qword-sized increments, recording the
 * last qword-aligned cut that still fits within @budget payload
 * descriptors.  A qword spans at most HFI2_DMS_DESCS_PER_QWORD
 * descriptors, so a legal cut always exists within
 * [budget - HFI2_DMS_DESCS_PER_QWORD, budget].
 */
static void hfi2_dms_fill_qword_search(struct hfi2_dms_fill_cursor *cur,
				       struct sdma_desc const *base, u64 cap,
				       u64 *filled, u32 budget,
				       struct hfi2_dms_fill_cursor *best,
				       u64 *best_filled, bool is_jkr)
{
	while (*filled < cap) {
		u64 to_qword = HFI2_DMS_DESCS_PER_QWORD - (*filled & 7);
		u64 max_bytes = min(to_qword, cap - *filled);
		u64 step = hfi2_dms_fill_bounded_step(cur, max_bytes, is_jkr);

		if (cur->err)
			return;

		*filled += step;

		if ((*filled & 7) == 0) {
			if ((u64)(cur->cur_desc - base) <= budget) {
				*best = *cur;
				*best_filled = *filled;
			} else {
				break;
			}
		}
	}
}

/*
 * Fill up to @cap bytes of one DATA sub-packet payload, ending on a qword
 * boundary with no more than @budget payload descriptors.  Source runs are
 * emitted wholesale; only the single run that would exceed @budget is undone
 * and re-emitted qword-by-qword to find the largest legal cut.  Returns the
 * payload byte count committed (always a qword multiple, since @cap is).
 */
static u64 hfi2_dms_fill_one_subpacket(struct hfi2_dms_fill_cursor *cur,
				       u64 cap, u32 budget, bool is_jkr)
{
	struct sdma_desc const *base = cur->cur_desc;
	struct hfi2_dms_fill_cursor best = *cur;
	u64 best_filled = 0;
	u64 filled = 0;

	while (filled < cap) {
		struct hfi2_dms_fill_cursor save = *cur;
		u64 save_filled = filled;
		u64 step = hfi2_dms_fill_bounded_step(cur, cap - filled, is_jkr);

		if (cur->err)
			return 0;

		filled += step;

		if ((u64)(cur->cur_desc - base) <= budget) {
			if ((filled & 7) == 0 || filled == cap) {
				best = *cur;
				best_filled = filled;
			}
			continue;
		}

		*cur = save;
		filled = save_filled;
		hfi2_dms_fill_qword_search(cur, base, cap, &filled, budget,
					   &best, &best_filled, is_jkr);
		if (cur->err)
			return 0;
		break;
	}

	if (filled == cap && (u64)(cur->cur_desc - base) <= budget)
		return cap;

	*cur = best;
	return best_filled;
}

/*
 * Initialise one DATA-packet AHG header in place from the per-port
 * template.  The full template copy is mandatory: AHG slots are recycled
 * across message types, so stale WRITE_START/DATA_START fields must be
 * cleared every time.
 */
static void hfi2_dms_impl_emit_data_header(struct hfi2_dms *dms,
					   struct hfi2_dms_mem_coh *hdr,
					   u8 port_idx, u32 dlid,
					   hfi2_dms_rift_key_t tx_rift_key,
					   u8 rx_id, u16 generation, u16 entropy,
					   enum hfi2_dms_msg_type msg_type,
					   u64 order_key)
{
	union hfi2_dms_proto_cmd_data const *data_template =
		(union hfi2_dms_proto_cmd_data *)
		&dms->protocol_cmd_templates[port_idx][msg_type];
	u32 payload_dws = HFI2_DMS_MAX_PAYLOAD_SIZE >> 2;
	u32 pbc_pktlen_dws =
		hfi2_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
	u32 pktlen_qws = pbc_pktlen_dws >> 1;
	union hfi2_dms_proto_cmd_data *cmd =
		(union hfi2_dms_proto_cmd_data *)hdr->kvaddr;
	u64 j;

	for (j = 0; j < ARRAY_SIZE(cmd->qws); j++)
		cmd->qws[j] = data_template->qws[j];

	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi2_dms_impl_pbc_length_dws_set(&cmd->pbc, pbc_pktlen_dws);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pktlen_qws);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, _dms_route_control_for_order_key(order_key));
	/*
	 * Every DATA packet of this request carries the same entropy so the
	 * fabric keeps them on one in-order (SLID,DLID,entropy) path matching
	 * the SDMA engine chosen by _dms_sdma_engine_idx_from_entropy().
	 */
	hfi2_dms_impl_lrh16bc_entropy_set(&cmd->lrh16bc, entropy);
	_dms_destqp_rx_set(&cmd->info.bth[0], rx_id);
	cmd->info.tx_rift_key = tx_rift_key;
	cmd->info.generation = generation;
}

static u16 _dms_entropy_next(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);
	/* u16 wrap is intentional: entropy is a spread seed, not an identity. */
	return dms->entropy_next++;
}

/*
 * Pick an SDMA engine from a per-request entropy value, division-free:
 *   1. entropy * 0x9E37  -- Fibonacci (golden-ratio) hash; scatters the
 *      sequential entropy counter so adjacent requests hit different engines.
 *   2. (hashed * num_engines) >> 16  -- folds the 16-bit hash into
 *      [0, num_engines) with no modulo. Uniform for any engine count.
 */
static enum hfi2_dms_sdma_engine_idx
_dms_sdma_engine_idx_from_entropy(struct hfi2_dms *dms, u16 entropy)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(dms->num_engines <= 0);

	u16 const hashed = (u16)((u32)entropy * 0x9E37u);

	return (enum hfi2_dms_sdma_engine_idx)(((u32)hashed *
						   dms_num_data_engines(dms)) >> 16);
}

/*
 * Find an engine with room for @ndesc_needed descriptors.  With shared
 * engines (lanes > 1) the engine is returned with its hfi2_dms_sde_lock()
 * held so that no other lane can claim the room before
 * _sdma_engine_write_desc_stack() fills it and drops the lock.  Callers
 * must go straight from a successful acquire to that write: no exit path
 * and nothing that sleeps in between.  The engine's open desc_place() run
 * (another lane's IPoIB packets) is padded first, so the stack starts on a
 * granule boundary.  For sparse, the held lock is handed over with a
 * __release() here and an __acquire() there.
 */
static struct sdma_engine *
_sdma_engine_acquire(struct hfi2_dms *dms,
		     enum hfi2_dms_sdma_engine_idx const engine_idx,
		     u64 ndesc_needed)
{
	u32 cur_sdma_engine;
	u32 sdma_engine_count;
	u32 num_sdma_engines;
	int gethead;
	struct sdma_engine *sdma;

	DMS_BUG_ON(!dms);

	if (engine_idx != HFI2_DMS_SDMA_ENGINE_IDX_ANY) {

		if (WARN_ON_ONCE(engine_idx >= dms_num_data_engines(dms)))
			return NULL;
		sdma = dms->sdma_engines[engine_idx];
		DMS_BUG_ON(!sdma);

		hfi2_dms_sde_lock(dms, engine_idx);
		hfi2_dms_sdma_close_run(dms, engine_idx);
		if (!__sdma_running(sdma))
			goto busy;

		if (sdma_descq_freecnt(sdma) < ndesc_needed) {
			sdma_gethead_dma(sdma);
			if (sdma_descq_freecnt(sdma) < ndesc_needed)
				goto busy;
		}

		__release(&dms->sde_share[engine_idx].lock);
		return sdma;
busy:
		hfi2_dms_sde_unlock(dms, engine_idx);
		return NULL;
	}

	num_sdma_engines = dms_num_data_engines(dms);
	for (gethead = 0; gethead < 2; gethead++) {
		cur_sdma_engine = dms->cur_sdma_engine;
		for (sdma_engine_count = 0; sdma_engine_count < num_sdma_engines; sdma_engine_count++) {
			if (unlikely(cur_sdma_engine >= num_sdma_engines))
				cur_sdma_engine = 0; // keep range [0..num_sdma_engines)
			sdma = dms->sdma_engines[cur_sdma_engine];
			DMS_BUG_ON(!sdma);
			hfi2_dms_sde_lock(dms, cur_sdma_engine);
			hfi2_dms_sdma_close_run(dms, cur_sdma_engine);
			if (gethead != 0)
				sdma_gethead_dma(sdma);
			if (__sdma_running(sdma) && sdma_descq_freecnt(sdma) >= ndesc_needed) {
				dms->cur_sdma_engine = cur_sdma_engine;
				__release(&dms->sde_share[cur_sdma_engine].lock);
				return sdma;
			}
			hfi2_dms_sde_unlock(dms, cur_sdma_engine);
			++cur_sdma_engine;
		} // for sdma_engine_count
	} // for gethead

	return NULL;
}

static u64 _sdma_desc_stack_finalize(struct hfi2_dms *dms, struct hfi2_dms_impl_fill_state current_fill_state, u64 *pad_out)
{
	struct sdma_desc *last_desc;
	u64 ndesc_filled;
	struct sdma_desc *tail;
	u64 pad_needed;

	last_desc = current_fill_state.cur_desc - 1;
	ndesc_filled = (u64) (current_fill_state.cur_desc - dms->desc_stack);
	if (dms->chip_type == CHIP_JKR) {
		u64 pad_total = (HFI2_DMS_DESC_CHUNK_SIZE -
				 (ndesc_filled & (HFI2_DMS_DESC_CHUNK_SIZE - 1))) &
				(HFI2_DMS_DESC_CHUNK_SIZE - 1);
		struct sdma_desc *p;
		u64 last_pkt = 1;
		u64 room, pad_in_last;

		/*
		 * Absorb as much CHUNK-rounding padding as fits into the final
		 * packet, ahead of its head-to-host tail, so the dead
		 * descriptors ride at the very end of the submission rather than
		 * delaying an earlier packet's egress and throttling the
		 * single-threaded op->ACK pipeline. Only the overflow (last
		 * packet already at MAX_DESC) is returned for the caller to
		 * front-distribute across earlier packets.
		 */
		for (p = last_desc - 1;
		     p >= dms->desc_stack && !jkr_sdma_qw_get_last_desc(&p->qw[0]);
		     --p)
			last_pkt++;
		room = MAX_DESC - last_pkt;
		pad_in_last = min(pad_total, room);

		tail = last_desc + pad_in_last;
		*tail = *last_desc;
		jkr_sdma_qw_set_head_to_host(&tail->qw[0]);
		for (u64 i = 0; i < pad_in_last; ++i)
			last_desc[i] = (struct sdma_desc){0};

		ndesc_filled += pad_in_last;
		pad_needed = pad_total - pad_in_last;
	} else if (dms->chip_type == CHIP_CYR) {
		tail = last_desc;
		cyr_sdma_qw_set_head_to_host(&tail->qw[0]);
		pad_needed = 0;

	} else {
		WARN_ON_ONCE(1); // Unknown chip type
		pad_needed = 0;
	}

	*pad_out = pad_needed;
	return ndesc_filled;
}

static void _sdma_engine_write_desc_stack(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx engine_idx, struct sdma_engine *sdma, u64 ndesc_total, u64 npadding, struct hfi2_dms_ahg_header_set *ahg_set)
{
	u32 desc_tail;
	u32 descq_cnt;
	struct sdma_desc *desc;
	struct hfi2_dms_sde_rsrc *sdma_rsrc;

	// write all descriptors into the descriptor queue
	desc_tail = sdma->descq_tail;
	descq_cnt = sdma->descq_cnt;
	u64 i_f = 0;

	for (u64 i = 0; i < ndesc_total; ++i) {
		desc = &dms->desc_stack[i];
		/*
		 * _sdma_desc_stack_finalize already placed as much padding as
		 * fit trailing in the last packet; only its overflow reaches
		 * here (last packet was at MAX_DESC).  Spread that remainder
		 * into the earliest packets that have room.
		 */
		if (npadding && jkr_sdma_qw_get_last_desc(&desc->qw[0])) {
			u32 ndesc_this_packet = (i - i_f) + 1;
			while (ndesc_this_packet < MAX_DESC && npadding) {
				sdma->descq[desc_tail].qw[0] = 0;
				sdma->descq[desc_tail].qw[1] = 0;
				desc_tail += 1;
				if (desc_tail == descq_cnt) {
					desc_tail = 0;
				}
				ndesc_this_packet++;
				npadding--;
			}
			i_f = i + 1;
		}
		sdma->descq[desc_tail].qw[0] = cpu_to_le64(desc->qw[0]);
		sdma->descq[desc_tail].qw[1] = cpu_to_le64(desc->qw[1]);
		desc_tail += 1;
		if (desc_tail == descq_cnt) {
			desc_tail = 0;
		}
	}

	WARN_ON_ONCE(npadding);

	if (engine_idx == HFI2_DMS_SDMA_ENGINE_IDX_ANY) {
		engine_idx = dms->cur_sdma_engine;
		dms->cur_sdma_engine = (dms->cur_sdma_engine + 1) %
			dms_num_data_engines(dms);
	}

	if (dms->sde_share) {
		/* taken by _sdma_engine_acquire() */
		lockdep_assert_held(&dms->sde_share[engine_idx].lock);
		hfi2_dms_sde_seq_advance(dms, engine_idx, sdma->descq_tail,
					 desc_tail, descq_cnt);
		ahg_set->seq_end = dms->sde_share[engine_idx].seq;
	}
	sdma->descq_tail = desc_tail;
	smp_wmb();
	writeq(sdma->descq_tail, sdma->tail_csr);
	__acquire(&dms->sde_share[engine_idx].lock);
	hfi2_dms_sde_unlock(dms, engine_idx);
	sdma_rsrc = &dms->sde_rsrcs[engine_idx];
	ahg_set->desc_idx = desc_tail;
	hfi2_dms_impl_dlist_append(&sdma_rsrc->active_ahg_headers, &ahg_set->dlist);
}

/*
 * Send @nchunks recv_chunks as one SDMA submission. Chunk i lands in the TID
 * range its tid_info names and takes the next hfi2_dms_recv_chunk_count()
 * elements of @gather, each relative to @page_offset; its wire bytes are its
 * element lengths each rounded up to a quadword.
 *
 * All the chunks' DATA packets share one AHG header set and one descriptor
 * stack, so the submission is accepted or refused whole: -EAGAIN when the
 * engine has no room (park the whole request), -E2BIG when a multi-chunk
 * request needs more headers or descriptors than one submission holds (send
 * it chunk by chunk instead), -EMSGSIZE when a single chunk does (fatal).
 */
static int hfi2_dms_impl_sdma_send(struct hfi2_dms *dms,
			    enum hfi2_dms_sdma_engine_idx engine_idx,
			    u64 page_offset,
			    struct hfi2_dms_recv_chunk const *chunks, u8 nchunks,
			    struct hfi2_dms_gather const *gather,
			    u8 port_idx, u32 dlid, u8 rx_id,
			    hfi2_dms_rift_key_t tx_rift_key, u16 generation,
			    struct hfi2_dms_page_provider const *src_provider,
			    u16 entropy, enum hfi2_dms_msg_type msg_type,
			    u64 order_key)
{
	struct send_context *sc;
	u64 start;
	u32 tid_offset;
	u32 tid;
	struct hfi2_dms_fill_cursor cursor;
	struct hfi2_dms_impl_fill_state current_fill_state;
	struct hfi2_dms_ahg_header_set *ahg_set;
	u64 in_tid_bytes;
	u64 region_rem;
	u64 op_rem;
	u32 k = 0;
	bool is_jkr;
	u64 ndesc_total, padding_needed;
	struct sdma_engine *sdma;
	u64 end;
	u8 next_gather = 0;

	if (WARN_ON_ONCE(dms == NULL))
		return -EFAULT;
	if (WARN_ON_ONCE(!src_provider))
		return -EFAULT;

	dms_trace(dms_sdma_send, dms, src_provider);

	sc = dms->port_sctxts[port_idx];

	start = dms_rdtsc();
	// sdma still performs send context checks on egress
	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL)) {
		return -ENOMEM;
	}

	if (unlikely(!dms->desc_stack || dms->num_descs == 0 || !nchunks)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	is_jkr = dms->chip_type == CHIP_JKR;
	cursor = (struct hfi2_dms_fill_cursor){
		.cur_desc = &dms->desc_stack[0],
		.src_provider = src_provider,
		.page_offset = 0,
		.run_dma = NULL,
		.pad_desc = dms->pad_desc_template,
		.src_base = page_offset,
		.err = 0,
		.tail_desc = dms->tail_desc_template
	};
	if (dms->chip_type == CHIP_CYR)
		cyr_sdma_qw_set_send_ctxt_extension(&cursor.tail_desc.qw[0], sc->hw_context);

	for (u8 c = 0; c < nchunks; c++) {
		u32 const tid_info = chunks[c].tid_info;
		u8 const gather_count = hfi2_dms_recv_chunk_count(&chunks[c]);

		tid_offset = (tid_info & 0x7fff) << 2;
		tid = (tid_info >> 16) & 0x3ff;

		if (unlikely(tid_offset >= PAGE_SIZE || !gather_count)) {
			dms->counters.health_invalid_data_request++;
			goto err_put_ahg;
		}

		/* This chunk's elements; the cursor walks them like a one-chunk list. */
		cursor.gather = &gather[next_gather];
		cursor.gather_count = gather_count;
		cursor.pad_owed = 0;
		hfi2_dms_fill_elem_start(&cursor, 0);

		in_tid_bytes = tid_offset;
		region_rem = HFI2_DMS_MAX_PAYLOAD_SIZE - tid_offset;
		op_rem = 0;
		for (u8 i = 0; i < gather_count; i++)
			op_rem += round_up(cursor.gather[i].length, 8);
		next_gather += gather_count;

		/*
		 * Walk the chunk one TID region (HFI2_DMS_MAX_PAYLOAD_SIZE window) at a
		 * time, splitting each region into one or more same-TID DATA
		 * sub-packets so no single packet exceeds the descriptor budget.
		 */
		while (op_rem > 0) {
			struct hfi2_dms_mem_coh *hdr;
			union hfi2_dms_proto_cmd_data *cmd;
			struct hfi2_dms_fill_cursor fill_start;
			struct sdma_desc *hdr_desc;
			u64 descs_used = (u64)(cursor.cur_desc - dms->desc_stack);
			u64 cap;
			u64 bytes;

			if (unlikely(k >= HFI2_DMS_AHG_HEADERS_PER_SET))
				goto err_put_ahg_fatal;
			/*
			 * Reserve a full padded packet (MAX_DESC) plus the
			 * HFI2_DMS_DESCS_PER_QWORD transient slots the budget search
			 * may momentarily emit past the payload budget before
			 * retreating, so the fill never writes past desc_stack.
			 */
			if (unlikely(dms->num_descs - descs_used <
				     MAX_DESC + HFI2_DMS_DESCS_PER_QWORD))
				goto err_put_ahg_fatal;

			hdr = &ahg_set->headers[k];
			hfi2_dms_impl_emit_data_header(dms, hdr, port_idx, dlid,
						       tx_rift_key, rx_id, generation,
						       entropy, msg_type, order_key);
			cmd = (union hfi2_dms_proto_cmd_data *)hdr->kvaddr;
			cmd->info.kdeth[0] =
				hfi2_dms_tid_info_make(tid, in_tid_bytes >> 2);

			hdr_desc = cursor.cur_desc;
			*hdr_desc = dms->header_desc_template;
			_sdma_qw_set_phy_addr(&hdr_desc->qw[0], hdr->phys_addr);
			cursor.cur_desc += 1;

			cap = min(region_rem, op_rem);
			fill_start = cursor;
			bytes = hfi2_dms_fill_one_subpacket(&cursor, cap,
							    HFI2_DMS_PKT_PAYLOAD_DESC_BUDGET,
							    is_jkr);
			if (cursor.err)
				goto err_put_ahg;

			/*
			 * The op_rem/region_rem decrements below drive the loop toward
			 * termination and rely on the provider densely tiling the
			 * requested span. A zero fill is a non-tiling provider that
			 * would spin this loop forever on the single BTS thread, so
			 * treat it as a fatal contract violation rather than hanging
			 * the device.
			 */
			if (unlikely(bytes == 0))
				goto err_put_ahg_fatal;

			/*
			 * A packet of this length needs the PBC test bit.
			 * The DATA header size is fixed for the receive context,
			 * so it cannot be padded. Send fewer bytes in this packet
			 * and the rest in the next one: fill again from the start
			 * of this packet, stopping short by the trim. The shorter
			 * fill needs no more descriptors than the one it replaces,
			 * so it always returns everything asked of it. The next
			 * packet takes one more AHG header from the set; a
			 * request that runs out of them falls back chunk by chunk.
			 */
			if (unlikely(_dms_split_data_packet(bytes))) {
				u32 const budget = HFI2_DMS_PKT_PAYLOAD_DESC_BUDGET;
				u64 keep = ALIGN(bytes, sizeof(u64)) -
					   _dms_data_split_trim(bytes);

				cursor = fill_start;
				bytes = hfi2_dms_fill_one_subpacket(&cursor, keep, budget,
								    is_jkr);
				if (cursor.err)
					goto err_put_ahg;
				if (unlikely(bytes != keep))
					goto err_put_ahg_fatal;
			}

			if (bytes != HFI2_DMS_MAX_PAYLOAD_SIZE) {
				u32 payload_dws = (bytes + 3) >> 2;
				u32 pbc_pktlen_dws;
				u32 pktlen_qws;

				pbc_pktlen_dws =
					hfi2_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
				pktlen_qws = pbc_pktlen_dws >> 1;

				hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc,
								  pktlen_qws);
				hfi2_dms_impl_pbc_length_dws_set(&cmd->pbc,
								 pbc_pktlen_dws);
			}

			*cursor.cur_desc = cursor.tail_desc;
			cursor.cur_desc += 1;

			in_tid_bytes += bytes;
			region_rem -= bytes;
			op_rem -= bytes;
			k += 1;

			if (region_rem == 0) {
				tid += 1;
				in_tid_bytes = 0;
				region_rem = HFI2_DMS_MAX_PAYLOAD_SIZE;
			}
		}
	}

	/* Finalizing rewrites the last descriptor: there must be one. */
	if (WARN_ON_ONCE(!k))
		goto err_put_ahg;

	current_fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = cursor.cur_desc,
	};
	ndesc_total = _sdma_desc_stack_finalize(dms, current_fill_state, &padding_needed);
	if (unlikely(ndesc_total + padding_needed > dms->num_descs)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg_fatal;
	}
	/*
	 * A ring holds at most descq_cnt - 1 descriptors in flight (every
	 * engine shares the sdma_descq_cnt setting), so a submission larger
	 * than that is never accepted and would stay parked, blocking the
	 * engine's waitlist, until the stale timeout cancels the transfer.
	 * Send such a multi-chunk request chunk by chunk instead; a single
	 * chunk that large (only with a very small sdma_descq_cnt) fails.
	 */
	if (unlikely(ndesc_total + padding_needed >
		     dms->sdma_engines[0]->descq_cnt - 1u)) {
		if (nchunks > 1)
			goto err_put_ahg_fatal;
		hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free,
					   &ahg_set->dlist);
		dms->counters.sdma_desc_overflow++;
		return -EMSGSIZE;
	}

	sdma = _sdma_engine_acquire(dms, engine_idx, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	for (u32 i = 0; i < k; ++i)
		_sdma_header_pbc_test(dms, ahg_set->headers[i].kvaddr);

	_sdma_engine_write_desc_stack(dms, engine_idx, sdma, ndesc_total, padding_needed, ahg_set);

	/*
	 * Count the k DATA packets once the engine has them: a build refused
	 * for room is retried or rebuilt per chunk and counted then.
	 */
	if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
		dms->counters.tx_sent[msg_type] += k;

	end = dms_rdtsc();
	dms->counters.tid_send += end - start;

	return 0;

err_put_ahg:
	hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free, &ahg_set->dlist);
	return -EINVAL;

err_put_ahg_fatal:
	hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free, &ahg_set->dlist);
	/*
	 * A multi-chunk request too large for one submission is not an error:
	 * the caller sends it chunk by chunk instead, as before batching.
	 */
	if (nchunks > 1)
		return -E2BIG;
	/*
	 * A single chunk deterministically needs more descriptors or AHG
	 * headers than one submission provides; retrying the identical op
	 * cannot help, so signal a permanent failure (-EMSGSIZE) that
	 * _sdma_inject escalates to a tracker cancel rather than parking on
	 * the SDMA waitlist.
	 */
	WARN_ON_ONCE(1);
	dms->counters.sdma_desc_overflow++;
	return -EMSGSIZE;
}

int _inject_cmd_sdma(struct hfi2_dms *dms, union hfi2_dms_proto_cmd * cmd, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	u32 const count = 1;
	struct hfi2_dms_ahg_header_set *ahg_set;
	struct hfi2_dms_impl_fill_state current_fill_state;
	u64 ndesc_total, padding_needed;
	struct sdma_engine *sdma;
	struct sdma_desc *desc;
	struct hfi2_dms_mem_coh *ahg_header;
	u8 port_idx = _pbc_port_idx_get(cmd->pbc);
	struct send_context *sc = dms->port_sctxts[port_idx];

	// sdma still performs send context checks on egress
	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL)) {
		return -ENOMEM;
	}

	current_fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = &dms->desc_stack[0],
	};

	for (u32 i = 0; i < count; ++i) {
		ahg_header = &ahg_set->headers[i];
		memcpy(ahg_header->kvaddr, &cmd[i], sizeof(union hfi2_dms_proto_cmd_data));

		desc = current_fill_state.cur_desc;
		*desc = (struct sdma_desc){0};
		u32 const nbytes = (hfi2_dms_impl_pbc_length_dws_get(cmd[i].pbc) << 2) - sizeof(u64);
		_sdma_qw_set_byte_count(&desc->qw[0], nbytes);
		_sdma_qw_set_first_desc(&desc->qw[0]);
		_sdma_qw_set_header_mode(&desc->qw[0], SDMA_AHG_NO_AHG);
		_sdma_qw_set_phy_addr(&desc->qw[0], ahg_header->phys_addr);
		current_fill_state.cur_desc += 1;

		desc = current_fill_state.cur_desc;
		*desc = dms->tail_desc_template;
		if (dms->chip_type == CHIP_CYR)
			cyr_sdma_qw_set_send_ctxt_extension(&desc->qw[0], sc->hw_context);
		current_fill_state.cur_desc += 1;
	}

	ndesc_total = _sdma_desc_stack_finalize(dms, current_fill_state, &padding_needed);

	sdma = _sdma_engine_acquire(dms, engine_idx, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	_sdma_header_pbc_test(dms, ahg_set->headers[0].kvaddr);
	_sdma_engine_write_desc_stack(dms, engine_idx, sdma, ndesc_total, padding_needed, ahg_set);

	return 0;
}

