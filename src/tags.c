#include "weizz.h"

#define TAG_EQUALS(a, b) ((a).cmp_id == (b).cmp_id)

static u32 adjust_tags_counters(struct tag *tags, s32 i, u32 len, u16 new_cnt) {

  s32 span = (s32)tags[i].counter - (s32)new_cnt;
  s64 last_tg = -1;
  u32 ntypes = 0;
  
  for (; i < len; ++i) {
  
    if (tags[i].cmp_id != last_tg) ++ntypes;
    last_tg = tags[i].cmp_id;
    
    tags[i].counter = (s32)tags[i].counter - (s32)span;
  
  }
  
  return ntypes;

}

static u32 count_ntypes(struct tag *tags, s32 i, u32 len) {

  s64 last_tg = -1;
  u32 ntypes = 0;
  
  for (; i < len; ++i) {
  
    if (tags[i].cmp_id != last_tg) ++ntypes;
    last_tg = tags[i].cmp_id;
  
  }
  
  return ntypes;

}

/***** FIELDS ******/

static u32 search_field_end(struct tag *tags, struct tag *last, u32 i, u32 len,
                            u32 initial) {

  if ((initial -i) >= 8) return i;
  
  while (i < len && tags[i].cmp_id == last->cmp_id)
    ++i;

  /* One byte tolerance */

  if (i + 1 < len && tags[i + 1].cmp_id == last->cmp_id) {

    ++i;
    while (i < len && tags[i].cmp_id == last->cmp_id)
      ++i;

  }

  if (i < len && tags[i].counter == last->counter + 1) {

    i = search_field_end(tags, &tags[i], i, len, initial);

  }

  return i;

}

static void field_mutator(u8 *buf, s32 begin, s32 end) {

  switch (UR(12 + ((extras_cnt + a_extras_cnt) ? 1 : 0))) {

    case 0: {

      /* Flip a single bit somewhere. Spooky! */

      s32 bit_idx = ((UR(end - begin) + begin) << 3) + UR(8);

      FLIP_BIT(buf, bit_idx);

      break;

    }

    case 1: {

      /* Set byte to interesting value. */

      u8 val = interesting_8[UR(sizeof(interesting_8))];
      buf[(UR(end - begin) + begin)] = val;

      break;

    }

    case 2: {

      /* Set word to interesting value, randomly choosing endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      switch (UR(2)) {

        case 0:
          *(u16 *)(buf + byte_idx) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];
          break;
        case 1:
          *(u16 *)(buf + byte_idx) =
              SWAP16(interesting_16[UR(sizeof(interesting_16) >> 1)]);
          break;

      }

      break;

    }

    case 3: {

      /* Set dword to interesting value, randomly choosing endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      switch (UR(2)) {

        case 0:
          *(u32 *)(buf + byte_idx) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];
          break;
        case 1:
          *(u32 *)(buf + byte_idx) =
              SWAP32(interesting_32[UR(sizeof(interesting_32) >> 2)]);
          break;

      }

      break;

    }

    case 4: {

      /* Set qword to interesting value, randomly choosing endian. */

      if (end - begin < 8) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 7) break;

      switch (UR(2)) {

        case 0:
          *(u64 *)(buf + byte_idx) =
              (s64)interesting_32[UR(sizeof(interesting_32) >> 2)];
          break;
        case 1:
          *(u64 *)(buf + byte_idx) =
              SWAP64((s64)interesting_32[UR(sizeof(interesting_32) >> 2)]);
          break;

      }

      break;

    }

    case 5: {

      /* Randomly subtract from byte. */

      buf[(UR(end - begin) + begin)] -= 1 + UR(ARITH_MAX);

      break;

    }

    case 6: {

      /* Randomly add to byte. */

      buf[(UR(end - begin) + begin)] += 1 + UR(ARITH_MAX);

      break;

    }

    case 7: {

      /* Randomly subtract from word, random endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      if (UR(2)) {

        *(u16 *)(buf + byte_idx) -= 1 + UR(ARITH_MAX);

      } else {

        u16 num = 1 + UR(ARITH_MAX);

        *(u16 *)(buf + byte_idx) =
            SWAP16(SWAP16(*(u16 *)(buf + byte_idx)) - num);

      }

      break;

    }

    case 8: {

      /* Randomly add to word, random endian. */

      if (end - begin < 2) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 1) break;

      if (UR(2)) {

        *(u16 *)(buf + byte_idx) += 1 + UR(ARITH_MAX);

      } else {

        u16 num = 1 + UR(ARITH_MAX);

        *(u16 *)(buf + byte_idx) =
            SWAP16(SWAP16(*(u16 *)(buf + byte_idx)) + num);

      }

      break;

    }

    case 9: {

      /* Randomly subtract from dword, random endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      if (UR(2)) {

        *(u32 *)(buf + byte_idx) -= 1 + UR(ARITH_MAX);

      } else {

        u32 num = 1 + UR(ARITH_MAX);

        *(u32 *)(buf + byte_idx) =
            SWAP32(SWAP32(*(u32 *)(buf + byte_idx)) - num);

      }

      break;

    }

    case 10: {

      /* Randomly add to dword, random endian. */

      if (end - begin < 4) break;

      s32 byte_idx = (UR(end - begin) + begin);

      if (byte_idx >= end - 3) break;

      if (UR(2)) {

        *(u32 *)(buf + byte_idx) += 1 + UR(ARITH_MAX);

      } else {

        u32 num = 1 + UR(ARITH_MAX);

        *(u32 *)(buf + byte_idx) =
            SWAP32(SWAP32(*(u32 *)(buf + byte_idx)) + num);

      }

      break;

    }

    case 11: {

      /* Just set a random byte to a random value. Because,
         why not. We use XOR with 1-255 to eliminate the
         possibility of a no-op. */

      buf[(UR(end - begin) + begin)] ^= 1 + UR(255);

      break;

    }

      /* Value12  can be selected only if there are any extras
         present in the dictionaries. */

    case 12: {

      /* Overwrite bytes with an extra. */

      if (!extras_cnt || (a_extras_cnt && UR(2))) {

        /* No user-specified extras or odds in our favor. Let's use an
           auto-detected one. */

        u32 use_extra = UR(a_extras_cnt);
        u32 extra_len = a_extras[use_extra].len;
        u32 insert_at;

        if (extra_len > end - begin) break;

        s32 byte_idx = 0;
        if (extra_len != end - begin)
          byte_idx = (UR(end - begin - extra_len) + begin);

        insert_at = byte_idx;
        memcpy(buf + insert_at, a_extras[use_extra].data, extra_len);

      } else {

        /* No auto extras or odds in our favor. Use the dictionary. */

        u32 use_extra = UR(extras_cnt);
        u32 extra_len = extras[use_extra].len;
        u32 insert_at;

        if (extra_len > end - begin) break;

        s32 byte_idx = 0;
        if (extra_len != end - begin)
          byte_idx = (UR(end - begin - extra_len) + begin);

        insert_at = byte_idx;
        memcpy(buf + insert_at, extras[use_extra].data, extra_len);

      }

      break;

    }

  }

}

static void search_field_boundaries(struct tag *tags, s32 i, u32 len, s32 *start,
                                    s32 *end) {

  u32 k = i;
  while (k > 0 && TAG_EQUALS(tags[i], tags[k]))
    --k;

  if (k > 1 && TAG_EQUALS(tags[i], tags[k -2])) {
    k -= 2;
    while (k > 0 && TAG_EQUALS(tags[i], tags[k]))
      --k;
  }
  
  *start = k;
  *end = search_field_end(tags, &tags[i], i, len, i);

  // DBGPRINT(" %d <= %d\n", *start, *end);
  // DBGASSERT(*start <= *end && *start >= 0 && *end >= 0);

}

static int get_random_field(struct tags_info *ti, s32 len, s32* start, s32* end, u8 for_mut) {

  s32 i, j;

  if (UR(2)) {

    for (i = UR(len); i < len;) {

      if (ti->tags[i].cmp_id == 0) {

        ++i;
        continue;

      }

      // u16 cmp_id = ti->tags[i].cmp_id;

      search_field_boundaries(ti->tags, i, len, &i, &j);

      /* 1/3 probability to mutate input-to-states */
      if (!for_mut || !(ti->tags[i].flags & TAG_IS_INPUT_TO_STATE) ||
          UR(3) == 0) {

        *start = i;
        *end = j;
        return 0;

      }

      /*if (!(ti->tags[i].flags & TAG_IS_INPUT_TO_STATE) &&
          (pass_stats[cmp_id].total == 0 ||
           UR(pass_stats[cmp_id].total) >= pass_stats[cmp_id].failed))
        field_mutator(buf, i, j);*/

      i = j;

    }

  } else if (ti->ntypes) {

    u32 idx = UR(ti->ntypes);
    
    s64 last_tg = -1;

    s32 k = 0;
    s32 i, j;

    for (i = 0; i < len; ++i) {

      if (k == idx) {
      
        if (ti->tags[i].cmp_id == 0) {
          idx++;
          goto bail_out_field;
        }
      
        j = search_field_end(ti->tags, &ti->tags[i], i, len, i);

        *start = i;
        *end = j;
        return 0;

      }

bail_out_field:
      if (last_tg != ti->tags[i].cmp_id) ++k;
      last_tg = ti->tags[i].cmp_id;

    }
  
  }
  
  return 1;

}

static void mutate_random_field(struct tags_info *ti, u8 *buf, s32 len) {

  s32 i, j;
  if (get_random_field(ti, len, &i, &j, 1))
    return;
  
  field_mutator(buf, i, j);

}

/*
static int field_of_type(struct tags_info *ti, u8 *buf, s32 len, u16 type,
                         s32* start, s32* end) {

  s32 i, j; //TODO complete
  
  for (i = UR(len); i < len;) {

    if (ti->tags[i].cmp_id != type) {

      ++i;
      continue;

    }

    u16 cmp_id = ti->tags[i].cmp_id;

    search_field_boundaries(ti->tags, i, len, start, end);
    return 1;

  }
  
  return 0;

}
*/

/***** CHUNKS ******/

static u32 search_chunk_end(struct tag *tags, struct tag *last, s32 i, u32 len) {

  while (i < len && TAG_EQUALS(tags[i], last[0]))
    ++i;

  /* One byte tolerance */

  if (i + 1 < len && TAG_EQUALS(tags[i + 1], last[0])) {

    ++i;
    while (i < len && TAG_EQUALS(tags[i], last[0]))
      ++i;

  }

  if (i + 1 < len && tags[i +1].counter >= last->counter)
    ++i;
  
  while (i < len && tags[i].counter >= last->counter) {

    i = search_chunk_end(tags, &tags[i], i, len);

  }

  while (i < len && TAG_EQUALS(tags[i], last[0]))
    ++i;

  /* One byte tolerance */

  if (i + 1 < len && TAG_EQUALS(tags[i + 1], last[0])) {

    ++i;
    while (i < len && TAG_EQUALS(tags[i], last[0]))
      ++i;

  }

  /* Use the parent to get fields that are placed at the end but checked before
   the first field */

  if (i < len && tags[i].cmp_id == last->parent) {

    while (i < len && tags[i].cmp_id == last->parent)
      ++i;

  }

  /* Consider to include untagged parts*/

  if (UR(2) == 0) {

    while (i < len && tags[i].cmp_id == 0)
      ++i;
    
    if (i + 1 < len && tags[i +1].counter >= last->counter)
      ++i;

    while (i < len && tags[i].counter >= last->counter) {

      i = search_chunk_end(tags, &tags[i], i, len);

    }

  }

  return i;

}

/*
static u32 reverse_search_chunk_end(struct tag *tags, struct tag *tgt, s32 i, u32 len) {

  // TODO insert in mutations

  while (i >= 0 && TAG_EQUALS(tags[i], tgt[0]))
    --i;

  while (i >= 0 && tags[i].counter > tgt->counter) {

    i = reverse_search_chunk_end(tags, tgt, i, len);

  }

  return i;

}*/


static void search_chunk_boundaries(struct tag *tags, s32 i, u32 len, s32 *start,
                                    s32 *end) {

  u32 k = i;
  while (k > 0 && TAG_EQUALS(tags[i], tags[k]))
    --k;

  if (k > 1 && TAG_EQUALS(tags[i], tags[k -2])) {
    k -= 2;
    while (k > 0 && TAG_EQUALS(tags[i], tags[k]))
      --k;
  }
  
  *start = k;
  *end = search_chunk_end(tags, &tags[i], i, len);

  // DBGPRINT(" %d <= %d\n", *start, *end);
  // DBGASSERT(*start <= *end && *start >= 0 && *end >= 0);

}

static u32 search_next_its(struct tag *tags, struct tag *last, u32 i, u32 len) {

  while (i < len && TAG_EQUALS(tags[i], last[0]))
    ++i;

  /* One byte tolerance */

  if (i + 1 < len && TAG_EQUALS(tags[i + 1], last[0])) {

    ++i;
    while (i < len && TAG_EQUALS(tags[i], last[0]))
      ++i;

  }

  while (i < len && !(tags[i].flags & TAG_IS_INPUT_TO_STATE))
    ++i;

  return i;

}

static u32 search_next_rnd(struct tag *tags, struct tag *last, u32 i, u32 len) {

  while (i < len && TAG_EQUALS(tags[i], last[0]))
    ++i;

  if (len -i <= 0) return i;
  
  s32 off = UR(len -i) +i;
  
  i = off;
  while (i < len && TAG_EQUALS(tags[i], tags[off]))
    ++i;

  return i;

}

static u8 get_chunk_of_type(struct tag *tags, u32 len, u16 type, u32 target_len, u8 build_kind, u32 *start, u32*end) {

  u8 last_is_type_ok = 0;
  
  s32 ri = UR(len);

  s32 i, j;
  for (i = ri; i < len; ++i) {

    if (tags[i].cmp_id == type && !last_is_type_ok) {
    
      last_is_type_ok = 1;

      switch (build_kind) {
        case 0:
        case 1:
          j = search_chunk_end(tags, &tags[i], i, len);
          break;
        case 2:
          j = search_next_rnd(tags, &tags[i], i, len);
          break;
        case 3:
          j = search_field_end(tags, &tags[i], i, len, i);
          break;
      }
      
      if ((j - i) > target_len) continue;

      *start = i;
      *end = j;
      return 0;

    } else last_is_type_ok = 0;

  }
  
  for (i = 0; i < ri; ++i) {

    if (tags[i].cmp_id == type && !last_is_type_ok) {

      switch (build_kind) {
        case 0:
        case 1:
          j = search_chunk_end(tags, &tags[i], i, len);
          break;
        case 2:
          j = search_next_rnd(tags, &tags[i], i, len);
          break;
        case 3:
          j = search_field_end(tags, &tags[i], i, len, i);
          break;
      }

      if ((j - i) > target_len) continue;

      *start = i;
      *end = j;
      return 0;

    } else last_is_type_ok = 0;

  }

  return 1;

}

static u8 get_chunk_of_parent(struct tag *tags, u32 len, u16 parent, u8 build_kind, u32 *start, u32*end) {

  s32 ri = UR(len);

  s32 i, j;
  for (i = ri; i < len; ++i) {

    if (tags[i].parent == parent) {

      switch (build_kind) {
        case 0:
        case 1:
          j = search_chunk_end(tags, &tags[i], i, len);
          break;
        case 2:
          j = search_next_rnd(tags, &tags[i], i, len);
          break;
        case 3:
          j = search_field_end(tags, &tags[i], i, len, i);
          break;
      }

      *start = i;
      *end = j;
      return 0;

    } 

  }
  
  for (i = 0; i < ri; ++i) {

    if (tags[i].parent == parent) {

      switch (build_kind) {
        case 0:
        case 1:
          j = search_chunk_end(tags, &tags[i], i, len);
          break;
        case 2:
          j = search_next_rnd(tags, &tags[i], i, len);
          break;
        case 3:
          j = search_field_end(tags, &tags[i], i, len, i);
          break;
      }

      *start = i;
      *end = j;
      return 0;

    }

  }

  return 1;

}

/* Get all data chunks of a specific type */
// TODO evaluate if use this
/*
static struct worklist *get_chunks_between_its(struct tag *tags, u32 len,
                                               s32 *number) {

  struct worklist *chunks = NULL;
  struct worklist *tmp;
  (*number) = 0;

  s32 i, j;
  for (i = 0; i < len;) {

    if (tags[i].flags & TAG_IS_INPUT_TO_STATE) {

      j = search_next_its(tags, &tags[i], i, len);

      tmp              = ck_alloc_nozero(sizeof(struct worklist));
      tmp->chunk_start = i;
      tmp->chunk_end   = j;
      tmp->next        = chunks;
      chunks           = tmp;
      (*number)++;

      i = j;

    } else

      ++i;

  }

  return chunks;

}
*/


static int get_field_from_type_index(struct tag *tags, u32 len, u32 idx, s32* start, s32* end) {

  s64 last_tg = -1;

  s32 k = 0;
  s32 i, j;

  for (i = 0; i < len; ++i) {

    if (k == idx) {

      if (tags[i].cmp_id == 0) {
      
        s32 ni = i;
        while (ni < len && tags[ni].cmp_id == 0) ni++;
        if (ni == len) {
          *start = i;
          *end = len;
          return 0;
        }
        
        j = search_field_end(tags, &tags[ni], ni, len, ni);
        i = ni;
      
      } else j = search_field_end(tags, &tags[i], i, len, i);
 
      *start = i;
      *end = j;
      return 0;

    }

    if (last_tg != tags[i].cmp_id) ++k;
    last_tg = tags[i].cmp_id;

  }

  return 1;

}

static int get_rnd_chunk_from_type_index(struct tag *tags, u32 len, u32 idx, s32* start, s32* end) {

  s64 last_tg = -1;

  s32 k = 0;
  s32 i, j;

  for (i = 0; i < len; ++i) {

    if (k == idx) {
    
      if (tags[i].cmp_id == 0) {
      
        s32 ni = i;
        while (ni < len && tags[ni].cmp_id == 0) ni++;
        if (ni == len) {
          *start = i;
          *end = len;
          return 0;
        }
        
        j = search_next_rnd(tags, &tags[ni], ni, len);
      
      } else j = search_next_rnd(tags, &tags[i], i, len);
    
      *start = i;
      *end = j;
      return 0;

    }

    if (last_tg != tags[i].cmp_id) ++k;
    last_tg = tags[i].cmp_id;

  }

  return 1;

}

static int get_chunk_from_type_index(struct tag *tags, u32 len, u32 idx, s32* start, s32* end) {

  s64 last_tg = -1;

  s32 k = 0;
  s32 i, j;
  for (i = 0; i < len; ++i) {

    if (k == idx) {
    
      if (tags[i].cmp_id == 0) {
      
        s32 ni = i;
        while (ni < len && tags[ni].cmp_id == 0) ni++;
        if (ni == len) {
          *start = i;
          *end = len;
          return 0;
        }
        
        j = search_chunk_end(tags, &tags[ni], ni, len);
      
      } else j = search_chunk_end(tags, &tags[i], i, len);

      *start = i;
      *end = j;
      return 0;

    }

    if (last_tg != tags[i].cmp_id) ++k;
    last_tg = tags[i].cmp_id;

  }

  return 1;

}


static u8 get_random_chunk(struct tags_info *tags, s32 temp_len, s32 *chunk_start,
                           s32 *chunk_end, u8 build_kind) {

  u32 chunk_type_id;

  if (tags->ntypes == 0) return 1;

  switch (build_kind) {

    case 0:
    case 1: {

      chunk_type_id = UR(tags->ntypes);
      return get_chunk_from_type_index(tags->tags, temp_len, chunk_type_id,
                                           chunk_start, chunk_end);
    }

    case 2: {

      /*targets =
          get_chunks_between_its(tags->tags, temp_len, &same_type_chunks_num);*/
      
      chunk_type_id = UR(tags->ntypes);
      return get_rnd_chunk_from_type_index(tags->tags, temp_len, chunk_type_id,
                                           chunk_start, chunk_end);
    }
    
    case 3: {
    
      chunk_type_id = UR(tags->ntypes);
      return get_field_from_type_index(tags->tags, temp_len, chunk_type_id,
                                           chunk_start, chunk_end);
    }

  }

  return 1;

}


#define BUILD_KINDS 3

u8 higher_order_fuzzing(struct tags_info **p_ti, s32 *temp_len, u8 **buf,
                        s32 alloc_size) {

  u8 changed_structure = 0;

  if (!(*temp_len)) return 0;

  u8 build_kind = UR(BUILD_KINDS);

  u32 s = UR(6);

  switch (s) {

    case 0: {                                               /* Delete chunk */
      s32 del_from, del_to;

      if (*temp_len < 2) break;

      if (get_random_chunk(*p_ti, *temp_len, &del_from, &del_to, build_kind))
          break;

      // avoid to have an empty buf
      if (del_to - del_from == (*temp_len)) break;

      // DBGPRINT(" TAGS DELETE %d %d\n", del_from, del_to);
      
      (*p_ti)->ntypes -= count_ntypes((*p_ti)->tags, del_from, del_to);

      memmove((*buf) + del_from, (*buf) + del_to, (*temp_len) - del_to);
      memmove((*p_ti)->tags + del_from, (*p_ti)->tags + del_to,
              ((*temp_len) - del_to) * sizeof(struct tag));
      (*temp_len) -= (del_to - del_from);

      changed_structure = 1;

      break;

    }

    case 1: {                                               /* Splice chunk */
      struct queue_entry *source_entry;
      u32                 tid;
      u8                  attempts = 20;
      u16                 type;
      u32                 target_len;
      s32                 target_start_byte = 0;
      s32                 target_end_byte   = 0;
      s32                 source_start_byte = 0;
      s32                 source_end_byte = 0;

      do {

        tid          = UR(tg_queued_num);
        source_entry = tg_queue;

        while (tid >= 100) {

          source_entry = source_entry->tg_next_100;
          tid -= 100;

        }

        while (source_entry && tid--)
          source_entry = source_entry->tg_next;

        while (source_entry &&
               (!source_entry->tags_fname || source_entry == queue_cur)) {

          source_entry = source_entry->tg_next;

        }

        attempts--;

      } while (!source_entry && attempts);

      if (attempts == 0) break;

      if (get_random_chunk(*p_ti, *temp_len, &target_start_byte,
                             &target_end_byte, build_kind))
        break;

      type = (*p_ti)->tags[target_start_byte].cmp_id;

      // DBGPRINT(" TAGS SPLICE  %d %d\n", target_start_byte, target_end_byte);

      target_len = target_end_byte - target_start_byte;

      u32  source_len = 0;

      struct tags_info *source_tags = ck_alloc_nozero(
          sizeof(struct tags_info) + source_entry->len * sizeof(struct tag));

      s32 fd = locked_open(source_entry->tags_fname, O_RDONLY);
      if (fd < 0) PFATAL("Unable to open '%s'", source_entry->tags_fname);

      ck_read(fd, source_tags,
              sizeof(struct tags_info) + source_entry->len * sizeof(struct tag),
              source_entry->tags_fname);

      close(fd);

      /* Find same type and non-bigger size in source */
      if (get_chunk_of_type(source_tags->tags, source_entry->len, type,
                            target_len, build_kind, &source_start_byte,
                            &source_end_byte)) {
        ck_free(source_tags);
        break;
      }

      source_len = source_end_byte - source_start_byte;

      u8 *source_buf;

      // DBGPRINT(" TAGS SPLICE OKKKKKKKK %d %d\n", source_start_byte,
      //         source_start_byte + source_len);

      /* Read the testcase into a new buffer. */

      fd = open(source_entry->fname, O_RDONLY);
      if (fd < 0) PFATAL("Unable to open '%s'", source_entry->fname);

      source_buf = ck_alloc_nozero(source_end_byte);

      ck_read(fd, source_buf, source_end_byte, source_entry->fname);

      close(fd);

      /* Apply the splicing to the output buffer */
      u32 move_amount = target_len - source_len;

      u32 tgt_ntypes = count_ntypes((*p_ti)->tags, target_start_byte, target_start_byte + source_len);

      memcpy((*buf) + target_start_byte, source_buf + source_start_byte,
             source_len);

      memmove((*buf) + target_start_byte + source_len,
              (*buf) + target_start_byte + target_len,
              (*temp_len) - target_start_byte - target_len);

      u32 src_ntypes = adjust_tags_counters(source_tags->tags, source_start_byte, source_end_byte, (*p_ti)->tags[target_start_byte].counter);
      
      (*p_ti)->ntypes -= tgt_ntypes;
      (*p_ti)->ntypes += src_ntypes;

      memcpy((*p_ti)->tags + target_start_byte,
             source_tags->tags + source_start_byte,
             source_len * sizeof(struct tag));

      memmove(
          (*p_ti)->tags + target_start_byte + source_len,
          (*p_ti)->tags + target_start_byte + target_len,
          ((*temp_len) - target_start_byte - target_len) * sizeof(struct tag));

      (*temp_len) -= move_amount;

      changed_structure = 1;

      /* The source buffer is no longer needed */
      ck_free(source_buf);
      ck_free(source_tags);

      break;

    }

    case 2: {

      struct queue_entry *source_entry;
      u32                 tid;
      u8                  attempts = 20;
      u16                 parent;
      s32                 target_start_byte = 0;
      s32                 target_end_byte   = 0;
      s32                 source_start_byte = 0;
      s32                 source_end_byte = 0;

      do {

        tid          = UR(tg_queued_num);
        source_entry = tg_queue;

        while (tid >= 100) {

          source_entry = source_entry->tg_next_100;
          tid -= 100;

        }

        while (source_entry && tid--)
          source_entry = source_entry->tg_next;

        while (source_entry &&
               (!source_entry->tags_fname || source_entry == queue_cur)) {

          source_entry = source_entry->tg_next;

        }

        attempts--;

      } while (!source_entry && attempts);

      if (attempts == 0) break;

      if (get_random_chunk(*p_ti, *temp_len, &target_start_byte,
                           &target_end_byte, build_kind))
        break;

      parent = (*p_ti)->tags[target_start_byte].parent;

      // DBGPRINT(" TAGS ADD %d %d\n", target_start_byte, target_end_byte);

      u32              source_len           = 0;

      struct tags_info *source_tags = ck_alloc_nozero(
          sizeof(struct tags_info) + source_entry->len * sizeof(struct tag));

      s32 fd = locked_open(source_entry->tags_fname, O_RDONLY);
      if (fd < 0) PFATAL("Unable to open '%s'", source_entry->tags_fname);

      ck_read(fd, source_tags,
              sizeof(struct tags_info) + source_entry->len * sizeof(struct tag),
              source_entry->tags_fname);

      close(fd);

      if (get_chunk_of_parent(source_tags->tags, source_entry->len, parent,
                            build_kind, &source_start_byte, &source_end_byte)) {
        ck_free(source_tags);
        break;                         
      }

      source_len = source_end_byte - source_start_byte;

      if (source_len > 0) {

        u8 *source_buf;

        // DBGPRINT(" TAGS ADD OKKKKKKKK %d %d\n", source_start_byte,
        //         source_start_byte + source_len);

        /* Read the testcase into a new buffer. */

        fd = open(source_entry->fname, O_RDONLY);
        if (fd < 0) PFATAL("Unable to open '%s'", source_entry->fname);

        source_buf = ck_alloc_nozero(source_end_byte);

        ck_read(fd, source_buf, source_end_byte, source_entry->fname);

        close(fd);

        u8 * new_buf  = ck_alloc_nozero(*temp_len + source_len);

        struct tags_info *new_tags = ck_alloc_nozero(
            sizeof(struct tags_info) + ((*temp_len) + source_len) * sizeof(struct tag));

        // fprintf(stderr, " new smart alloc %p %ld\n", new_tags,
        // ck_malloc_usable_size(new_tags));

        if (new_tags == NULL) {

          ck_free(source_buf);
          ck_free(source_tags);
          break;

        }

        u32 split_idx;
        switch (UR(2)) {

          case 0: split_idx = target_end_byte; break;
          case 1: split_idx = target_start_byte; break;

        }
        
        memcpy(new_buf, *buf, split_idx);
        memcpy(new_buf + split_idx, source_buf + source_start_byte,
               source_len);
        memcpy(new_buf + split_idx + source_len, (*buf) + split_idx,
               (*temp_len) - split_idx);

        u32 src_ntypes = adjust_tags_counters(source_tags->tags, source_start_byte, source_end_byte, (*p_ti)->tags[target_start_byte].counter);
        
        new_tags->ntypes = (*p_ti)->ntypes + src_ntypes;

        memcpy(new_tags->tags, (*p_ti)->tags, split_idx * sizeof(struct tag));
        memcpy(new_tags->tags + split_idx,
               source_tags->tags + source_start_byte,
               source_len * sizeof(struct tag));
        memcpy(new_tags->tags + split_idx + source_len,
               (*p_ti)->tags + split_idx,
               (*temp_len - split_idx) * sizeof(struct tag));

        (*temp_len) += source_len;

        ck_free(*buf);
        ck_free((*p_ti));

        (*buf) = new_buf;
        (*p_ti)    = new_tags;

        changed_structure = 1;
        ck_free(source_buf);
        ck_free(source_tags);

      }
        
      break;

    }

    /* 50% chance of field mutation */
    case 3 ... 5: {

      mutate_random_field(*p_ti, *buf, *temp_len);
      break;

    }

  }

  return changed_structure;

}

