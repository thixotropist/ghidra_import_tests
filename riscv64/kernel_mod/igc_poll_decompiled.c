
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong igc_poll(long *param_1,ulong param_2)

{
  undefined uVar1;
  ushort uVar2;
  ushort uVar3;
  undefined4 uVar4;
  int iVar5;
  char cVar6;
  void *pvVar7;
  long *plVar8;
  long lVar9;
  ulong uVar10;
  byte bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  long *plVar15;
  ulong *puVar16;
  long lVar17;
  short sVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  ulong uVar22;
  undefined8 *puVar23;
  long *plVar24;
  undefined8 *puVar25;
  undefined8 *puVar26;
  int iVar27;
  long *plVar28;
  int iVar29;
  long *plVar30;
  ulong uVar31;
  long *plVar32;
  long lVar33;
  long lVar34;
  long lVar35;
  int iVar36;
  ulong uVar37;
  undefined8 uVar38;
  long **pplVar39;
  long **pplVar40;
  ulong local_100;
  long local_f0;
  int local_e8;
  ulong local_e0;
  long local_d8;
  long local_c8;
  long local_c0;
  void *local_a8;
  ulong local_a0;
  void *local_98;
  long local_90;
  long **local_88;
  undefined8 uStack_80;
  ulong local_78;
  
  lVar33 = param_1[-3];
  pplVar39 = (long **)param_1[-6];
  iVar29 = (int)param_2;
  if (lVar33 != 0) {
    local_c0 = param_1[-9];
    uVar2 = *(ushort *)(lVar33 + 0x68);
    local_e0 = *(ulong *)(local_c0 + 0x38) >> 2 & 1;
    pplVar40 = pplVar39;
    if (local_e0 != 0) {
      if (pplVar39 == (long **)0x0) goto _L1812;
_L1810:
      plVar30 = pplVar40[0x28];
      uVar2 = *(ushort *)(pplVar39 + 0xd);
      uVar3 = *(ushort *)((long)pplVar39 + 0x6a);
      goto joined_r0x001072fe;
    }
    lVar34 = *(long *)(lVar33 + 0x20) + (ulong)uVar2 * 0x10;
    lVar9 = (long)(int)(uint)*(ushort *)(param_1 + -1);
    plVar30 = (long *)(*(long *)(lVar33 + 0x18) + (ulong)uVar2 * 0x38);
    uVar19 = (uint)uVar2 - (uint)*(ushort *)(lVar33 + 0x44);
    local_c8 = 0;
    puVar25 = (undefined8 *)0x0;
    uVar37 = 0;
    do {
      lVar35 = *plVar30;
      if ((lVar35 == 0) || (fence(), (*(uint *)(lVar35 + 0xc) & 1) == 0)) break;
      iVar12 = *(int *)(plVar30 + 2);
      *plVar30 = 0;
      uVar37 = (ulong)(*(int *)(plVar30 + 4) + (int)uVar37);
      puVar25 = (undefined8 *)(long)(int)((uint)*(ushort *)((long)plVar30 + 0x24) + (int)puVar25);
      if (iVar12 == 1) {
        xdp_return_frame(plVar30[3]);
_L2095:
        dma_unmap_page_attrs
                  (*(undefined8 *)(lVar33 + 0x10),plVar30[5],*(undefined4 *)(plVar30 + 6),1,0);
        *(undefined4 *)(plVar30 + 6) = 0;
      }
      else if (iVar12 == 2) {
        local_c8 = (long)((int)local_c8 + 1);
      }
      else {
        if (iVar12 == 0) {
          napi_consume_skb(plVar30[3],param_2);
          goto _L2095;
        }
        if (__print_once_22 == '\0') {
          __print_once_22 = '\x01';
          netdev_printk(&_LC7,*(undefined8 *)(lVar33 + 8),"Unknown Tx buffer type\n");
        }
      }
      while( true ) {
        plVar30 = plVar30 + 7;
        uVar19 = uVar19 + 1;
        if (lVar35 == lVar34) break;
        lVar34 = lVar34 + 0x10;
        if (uVar19 == 0) {
          plVar30 = *(long **)(lVar33 + 0x18);
          lVar34 = *(long *)(lVar33 + 0x20);
          uVar19 = -(uint)*(ushort *)(lVar33 + 0x44);
        }
        if (*(int *)(plVar30 + 6) != 0) {
          dma_unmap_page_attrs(*(undefined8 *)(lVar33 + 0x10),plVar30[5],*(int *)(plVar30 + 6),1,0);
          *(undefined4 *)(plVar30 + 6) = 0;
        }
      }
      lVar34 = lVar34 + 0x10;
      if (uVar19 == 0) {
        plVar30 = *(long **)(lVar33 + 0x18);
        lVar34 = *(long *)(lVar33 + 0x20);
        uVar19 = -(uint)*(ushort *)(lVar33 + 0x44);
      }
      lVar9 = (long)((int)lVar9 + -1);
    } while (lVar9 != 0);
    lVar35 = *(long *)(*(long *)(lVar33 + 8) + 0x400) + (ulong)*(byte *)(lVar33 + 0x46) * 0x140;
    lVar34 = lVar9;
    puVar26 = puVar25;
    if (uVar37 != 0) {
      dql_completed(lVar35 + 0xc0,uVar37);
      fence();
      if ((-1 < *(int *)(lVar35 + 0xc4) - *(int *)(lVar35 + 0xc0)) &&
         (uVar31 = *(ulong *)(lVar35 + 0x90),
         *(ulong *)(lVar35 + 0x90) = uVar31 & 0xfffffffffffffffd, (uVar31 & 2) != 0)) goto _L2109;
    }
    while( true ) {
      lVar9 = lVar33;
      *(short *)(lVar9 + 0x68) = *(short *)(lVar9 + 0x44) + (short)uVar19;
      lVar33 = param_1[-3];
      *(ulong *)(lVar33 + 0x78) = *(long *)(lVar33 + 0x78) + (uVar37 & 0xffffffff);
      *(ulong *)(lVar33 + 0x70) = *(long *)(lVar33 + 0x70) + ((ulong)puVar26 & 0xffffffff);
      *(int *)(param_1 + -2) = *(int *)(param_1 + -2) + (int)uVar37;
      *(int *)((long)param_1 + -0xc) = *(int *)((long)param_1 + -0xc) + (int)puVar26;
      lVar33 = *(long *)(lVar9 + 0x140);
      if (lVar33 == 0) break;
      if (local_c8 != 0) {
        xsk_tx_completed(local_c8);
        lVar33 = *(long *)(lVar9 + 0x140);
      }
      lVar33 = xsk_uses_need_wakeup(lVar33);
      if (lVar33 != 0) {
        xsk_set_tx_need_wakeup(*(undefined8 *)(lVar9 + 0x140));
      }
      lVar35 = *(long *)(lVar9 + 0x140);
      uVar4 = *(undefined4 *)(tp + 0x20);
      uVar37 = (ulong)*(ushort *)(lVar9 + 0x6a);
      local_a8 = (void *)0x0;
      local_a0 = 0;
      if ((*(ulong *)(*(long *)(lVar9 + 8) + 0x38) >> 2 & 1) != 0) break;
      lVar33 = *(long *)(*(long *)(lVar9 + 8) + 0x400) + (ulong)*(byte *)(lVar9 + 0x46) * 0x140;
      _raw_spin_lock(lVar33 + 0x80);
      iVar12 = 0;
      *(undefined4 *)(lVar33 + 0x84) = uVar4;
      if (*(ushort *)(lVar9 + 0x68) <= *(ushort *)(lVar9 + 0x6a)) {
        iVar12 = (int)*(short *)(lVar9 + 0x44);
      }
      uVar19 = ((*(ushort *)(lVar9 + 0x68) - 1) - (uint)*(ushort *)(lVar9 + 0x6a)) + iVar12;
      local_c8 = 0xffffffff;
      puVar25 = (undefined8 *)0x0;
      pplVar39 = pplVar40;
      while( true ) {
        uVar19 = uVar19 & 0xffff;
        lVar17 = xsk_tx_peek_desc(lVar35,&local_a8);
        if ((lVar17 == 0) || (uVar19 == 0)) {
          *(short *)(lVar9 + 0x6a) = (short)uVar37;
          if (puVar25 != (undefined8 *)0x0) {
            fence();
            fence();
            **(uint **)(lVar9 + 0x30) = (uint)*(ushort *)(lVar9 + 0x6a);
            if (*(short *)(&__mmiowb_state +
                          *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8)) != 0) {
              *(short *)(&DAT_0011c232 +
                        *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8)) =
                   *(short *)(&__mmiowb_state +
                             *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8));
            }
            xsk_tx_release(lVar35);
          }
          *(undefined4 *)(lVar33 + 0x84) = 0xffffffff;
          lVar35 = *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8);
          if (*(short *)(&DAT_0011c232 + lVar35) != 0) {
            *(undefined2 *)(&DAT_0011c232 + lVar35) = 0;
            fence();
          }
          *(short *)(&__mmiowb_state + lVar35) = *(short *)(&__mmiowb_state + lVar35) + -1;
          fence();
          *(short *)(lVar33 + 0x80) = (short)*(undefined4 *)(lVar33 + 0x80) + 1;
          goto _L1830;
        }
        lVar17 = (long)(int)(uint)local_a0;
        uVar31 = local_a0 & 0xffffffff;
        uVar38 = xp_raw_get_dma(lVar35,local_a8);
        if (*(char *)(lVar35 + 0xd6) != '\0') {
          xp_dma_sync_for_device_slow(lVar35,uVar38,local_a0 & 0xffffffff);
        }
        puVar25 = (undefined8 *)(*(long *)(lVar9 + 0x20) + uVar37 * 0x10);
        *puVar25 = uVar38;
        puVar25[1] = uVar31 | 0x2b300000 | lVar17 << 0x2e;
        puVar23 = (undefined8 *)(*(long *)(lVar9 + 0x18) + uVar37 * 0x38);
        *(undefined4 *)(puVar23 + 2) = 2;
        lVar17 = _jiffies;
        *(undefined4 *)((long)puVar23 + 0x24) = 1;
        puVar23[1] = lVar17;
        *(uint *)(puVar23 + 4) = (uint)local_a0;
        *puVar23 = puVar25;
        lVar17 = *(long *)(*(long *)(lVar9 + 8) + 0x400) + (ulong)*(byte *)(lVar9 + 0x46) * 0x140;
        if (0xfffffff < (uint)local_a0) break;
        *(uint *)(lVar17 + 200) = (uint)local_a0;
        *(uint *)(lVar17 + 0xc0) = (uint)local_a0 + *(int *)(lVar17 + 0xc0);
        if (*(int *)(lVar17 + 0xc4) - *(int *)(lVar17 + 0xc0) < 0) {
          *(ulong *)(lVar17 + 0x90) = *(ulong *)(lVar17 + 0x90) | 2;
          fence();
          if (-1 < *(int *)(lVar17 + 0xc4) - *(int *)(lVar17 + 0xc0)) {
            *(ulong *)(lVar17 + 0x90) = *(ulong *)(lVar17 + 0x90) & 0xfffffffffffffffd;
          }
        }
        uVar37 = (long)((int)uVar37 + 1) & 0xffff;
        if (*(ushort *)(lVar9 + 0x44) == uVar37) {
          uVar37 = 0;
        }
        uVar19 = uVar19 - 1;
      }
      ebreak();
_L2109:
      netif_schedule_queue(lVar35);
      lVar34 = lVar9;
      puVar26 = puVar25;
      pplVar40 = pplVar39;
    }
_L1830:
    local_e0 = *(ulong *)(lVar9 + 0x28) >> 5 & 1;
    if (((local_e0 != 0) &&
        (*(ulong *)(lVar9 + 0x28) = *(ulong *)(lVar9 + 0x28) & 0xffffffffffffffdf, *plVar30 != 0))
       && (((int)((uint)*(byte *)(local_c0 + 0x1a1) * 100) - _jiffies) + plVar30[1] < 0)) {
      uVar37 = igc_rd32(local_c0 + 0x298,8);
      if ((uVar37 & 0x10) != 0) goto _L1847;
      uVar38 = *(undefined8 *)(lVar9 + 8);
      uVar1 = *(undefined *)(lVar9 + 0x46);
      iVar12 = igc_rd32(local_c0 + 0x298,(uint)*(byte *)(lVar9 + 0x47) * 0x40 + 0xe010);
      fence();
      netdev_err(uVar38,
                 "Detected Tx Unit Hang\n  Tx Queue             <%d>\n  TDH                  <%x>\n  TDT                  <%x>\n  next_to_use          <%x>\n  next_to_clean        <%x>\nbuffer_info[next_to_clean]\n  time_stamp           <%lx>\n  next_to_watch        <%p>\n  jiffies              <%lx>\n  desc.status          <%x>\n"
                 ,uVar1,(long)iVar12,(long)**(int **)(lVar9 + 0x30),*(undefined2 *)(lVar9 + 0x6a),
                 *(undefined2 *)(lVar9 + 0x68),plVar30[1]);
      puVar16 = (ulong *)(*(long *)(*(long *)(lVar9 + 8) + 0x400) +
                          (ulong)*(byte *)(lVar9 + 0x46) * 0x140 + 0x90);
      *puVar16 = *puVar16 | 1;
      if (pplVar40 == (long **)0x0) {
        uVar37 = 0;
        goto _L1809;
      }
_L2096:
      local_c0 = param_1[-9];
      pplVar39 = (long **)param_1[-6];
      goto _L1810;
    }
_L1847:
    if ((puVar26 != (undefined8 *)0x0) && ((*(ulong *)(*(long *)(lVar9 + 8) + 0x38) >> 2 & 1) == 0))
    {
      sVar18 = 0;
      if (*(ushort *)(lVar9 + 0x68) <= *(ushort *)(lVar9 + 0x6a)) {
        sVar18 = *(short *)(lVar9 + 0x44);
      }
      if (((0x29 < (ushort)(((*(ushort *)(lVar9 + 0x68) - 1) - *(ushort *)(lVar9 + 0x6a)) + sVar18))
          && (fence(), (*(ulong *)(*(long *)(*(long *)(lVar9 + 8) + 0x400) +
                                   (ulong)*(byte *)(lVar9 + 0x46) * 0x140 + 0x90) & 1) != 0)) &&
         ((*(ulong *)(local_c0 + 0x38) >> 2 & 1) == 0)) {
        netif_tx_wake_queue();
        *(long *)(lVar9 + 0x80) = *(long *)(lVar9 + 0x80) + 1;
      }
    }
    local_e0 = (ulong)(lVar34 != 0);
    if (pplVar40 != (long **)0x0) goto _L2096;
    uVar37 = 0;
    goto _L1852;
  }
  if (pplVar39 != (long **)0x0) {
    local_c0 = param_1[-9];
    plVar30 = pplVar39[0x28];
    local_e0 = 1;
    uVar2 = *(ushort *)(pplVar39 + 0xd);
    uVar3 = *(ushort *)((long)pplVar39 + 0x6a);
joined_r0x001072fe:
    uVar31 = (ulong)uVar2;
    if (plVar30 != (long *)0x0) {
      iVar12 = 0;
      if (uVar31 <= uVar3) {
        iVar12 = (int)*(short *)((long)pplVar39 + 0x44);
      }
      plVar30 = (long *)((long)(int)(((uVar2 - 1) - (uint)uVar3) + iVar12) & 0xffff);
      uVar38 = *(undefined8 *)(local_c0 + 0xb00);
      if (0 < (long)param_2) {
        uVar37 = 0;
        uVar19 = 0;
        local_d8 = 0;
_L1871:
        plVar28 = pplVar39[4] + uVar31 * 2;
        uVar10 = (ulong)*(ushort *)((long)plVar28 + 0xc);
        iVar12 = (int)uVar37;
        if (uVar10 == 0) {
          uVar10 = (ulong)uVar19;
          *(short *)(pplVar39 + 0xd) = (short)uVar31;
          uVar22 = uVar37;
          goto joined_r0x001080b8;
        }
        fence();
        pplVar40 = (long **)(pplVar39[3] + uVar31 * 3);
        lVar33 = 0;
        if ((*(uint *)(plVar28 + 1) & 0x8000) != 0) {
          uVar10 = (ulong)(int)(*(ushort *)((long)plVar28 + 0xc) - 0x10);
          lVar33 = igc_ptp_rx_pktstamp(param_1[-9],**pplVar40);
          **pplVar40 = **pplVar40 + 0x10;
          (*pplVar40)[2] = (*pplVar40)[2] + 0x10;
        }
        (*pplVar40)[1] = **pplVar40 + (uVar10 & 0xffffffff);
        plVar15 = *pplVar40;
        if (*(char *)((long)pplVar39[0x28] + 0xd6) != '\0') {
          xp_dma_sync_for_cpu_slow(plVar15);
          plVar15 = *pplVar40;
        }
        lVar34 = __igc_xdp_run_prog(local_c0,uVar38,plVar15);
        if (lVar34 != 1) {
          if (1 < lVar34) {
            if (((uint)lVar34 - 2 & 0xfffffffd) == 0) {
              local_d8 = (long)(int)((uint)lVar34 | (uint)local_d8);
            }
            goto _L1869;
          }
          if (lVar34 != 0) goto _L1869;
          plVar8 = *pplVar40;
          plVar15 = (long *)param_1[-6];
          iVar13 = (int)plVar8[1] - (int)plVar8[2];
          uVar22 = *plVar8 - plVar8[2];
          lVar34 = __napi_alloc_skb(*plVar15 + 0x48,0x2a20);
          local_e8 = (int)uVar22;
          if (lVar34 == 0) {
            plVar15[0x12] = plVar15[0x12] + 1;
            goto _L1859;
          }
          uVar20 = *(uint *)(lVar34 + 0xbc);
          if (*(int *)(lVar34 + 0x74) != 0) goto _L2100;
          *(uint *)(lVar34 + 0xbc) = iVar13 + uVar20;
          *(int *)(lVar34 + 0x70) = *(int *)(lVar34 + 0x70) + iVar13;
          memcpy((void *)(*(long *)(lVar34 + 200) + (ulong)uVar20),(void *)plVar8[2],
                 (long)(iVar13 + 7) & 0xfffffff8);
          if (local_e8 != 0) {
            *(char *)(*(long *)(lVar34 + 200) + (ulong)*(uint *)(lVar34 + 0xc0) + 1) = (char)uVar22;
            uVar20 = *(int *)(lVar34 + 0x70) - local_e8;
            *(uint *)(lVar34 + 0x70) = uVar20;
            if (uVar20 < *(uint *)(lVar34 + 0x74)) goto _L2099;
            *(ulong *)(lVar34 + 0xd0) = *(long *)(lVar34 + 0xd0) + (uVar22 & 0xffffffff);
          }
          if (lVar33 != 0) {
            *(long *)(*(long *)(lVar34 + 200) + (ulong)*(uint *)(lVar34 + 0xc0) + 0x10) = lVar33;
          }
          lVar33 = igc_cleanup_headers(plVar15,plVar28,lVar34);
          if (lVar33 == 0) {
            igc_process_skb_fields(plVar15,plVar28,lVar34);
            napi_gro_receive(param_1,lVar34);
          }
        }
_L1859:
        xp_free(*pplVar40);
_L1869:
        *pplVar40 = (long *)0x0;
        uVar19 = uVar19 + (int)uVar10;
        uVar31 = (long)((int)uVar31 + 1) & 0xffff;
        uVar37 = (ulong)(iVar12 + 1);
        plVar30 = (long *)((long)((int)plVar30 + 1) & 0xffff);
        if (*(ushort *)((long)pplVar39 + 0x44) == uVar31) {
          uVar31 = 0;
        }
        if (param_2 == uVar37) goto _L0;
        goto _L1871;
      }
      uVar10 = 0;
      uVar19 = 0;
      uVar37 = 0;
      local_d8 = 0;
      uVar22 = 0;
      iVar12 = 0;
      goto _L1855;
    }
    plVar8 = pplVar39[0x1c];
    iVar12 = 0;
    if (uVar31 <= uVar3) {
      iVar12 = (int)*(short *)((long)pplVar39 + 0x44);
    }
    uVar10 = (long)(int)(((uVar2 - 1) - (uint)uVar3) + iVar12) & 0xffff;
    if (param_2 == 0) goto _L1966;
    local_f0 = 0;
    uVar37 = 0;
    uVar19 = 0;
    plVar28 = plVar8;
    do {
      local_a8 = (void *)0x0;
      local_a0 = 0;
      local_98 = (void *)0x0;
      local_90 = 0;
      local_88 = (long **)0x0;
      uStack_80 = 0;
      local_78 = 0;
      if (0xf < uVar10) {
        igc_alloc_rx_buffers(pplVar39,uVar10);
        uVar10 = 0;
      }
      plVar30 = pplVar39[4] + (ulong)*(ushort *)(pplVar39 + 0xd) * 2;
      uVar2 = *(ushort *)((long)plVar30 + 0xc);
      lVar33 = (long)(int)(uint)uVar2;
      plVar8 = plVar28;
      if (uVar2 == 0) break;
      fence();
      plVar32 = pplVar39[3] + (ulong)*(ushort *)(pplVar39 + 0xd) * 3;
      lVar34 = plVar32[1];
      if ((*(ulong *)(lVar34 + 8) & 1) != 0) {
        lVar34 = *(ulong *)(lVar34 + 8) - 1;
      }
      iVar12 = *(int *)(lVar34 + 0x34);
      dma_sync_single_for_cpu(pplVar39[2],(ulong)*(uint *)(plVar32 + 2) + *plVar32,2);
      cVar6 = pgtable_l5_enabled;
      *(short *)((long)plVar32 + 0x14) = *(short *)((long)plVar32 + 0x14) + -1;
      uVar31 = (ulong)(0x1000L << ((ulong)pplVar39[5] & 1)) >> 1;
      if (cVar6 == '\0') {
        if (pgtable_l4_enabled == '\0') {
          lVar9 = _kernel_map + -0x1000000000;
          lVar34 = 0x100000000;
        }
        else {
          lVar9 = _kernel_map + -0x200000000000;
          lVar34 = 0x20000000000;
        }
      }
      else {
        lVar9 = _kernel_map + -0x40000000000000;
        lVar34 = 0x4000000000000;
      }
      lVar35 = (plVar32[1] - (lVar9 - lVar34) >> 6) * 0x1000 + ___napi_schedule +
               (ulong)*(uint *)(plVar32 + 2);
      lVar34 = 0;
      lVar9 = 0;
      if (((ulong)(long)*(int *)(plVar30 + 1) >> 0xf & 1) == 0) {
        if (plVar28 == (long *)0x0) goto _L1889;
_L2128:
        if ((long *)0xfffffffffffff000 < plVar28) {
          uVar20 = (uint)plVar28;
          goto _L1892;
        }
        lVar9 = (long)(int)lVar33;
_L1891:
        uVar20 = (uint)((ulong)(0x1000L << ((ulong)pplVar39[5] & 1)) >> 1);
        skb_add_rx_frag(plVar8,*(undefined *)(plVar8[0x19] + (ulong)*(uint *)(plVar8 + 0x18) + 2),
                        plVar32[1],(long)*(int *)(plVar32 + 2),lVar9,(long)(int)uVar20);
        uVar21 = (uint)*(ushort *)((long)plVar32 + 0x14);
        puVar16 = (ulong *)plVar32[1];
        *(uint *)(plVar32 + 2) = *(uint *)(plVar32 + 2) ^ uVar20;
      }
      else {
        lVar33 = (long)(int)(uVar2 - 0x10);
        lVar34 = igc_ptp_rx_pktstamp(param_1[-9],lVar35);
        lVar9 = 0x10;
        if (plVar28 != (long *)0x0) goto _L2128;
_L1889:
        local_88 = pplVar39 + 0x20;
        local_78 = uVar31 & 0xffffffff;
        if (((ulong)pplVar39[5] >> 1 & 1) == 0) {
          if (*(long *)(**pplVar39 + 0xb00) != 0) {
            lVar35 = lVar35 + -0x100;
          }
        }
        else {
          lVar35 = lVar35 + -0x42;
        }
        lVar17 = 0x42;
        if (((ulong)pplVar39[5] >> 1 & 1) == 0) {
          lVar17 = (long)(int)((uint)(*(long *)(**pplVar39 + 0xb00) != 0) << 8);
        }
        local_a8 = (void *)(lVar9 + lVar17 + lVar35);
        local_a0 = (long)local_a8 + lVar33;
        lVar9 = (long)(int)lVar33;
        local_98 = local_a8;
        local_90 = lVar35;
        if (*(long *)(local_c0 + 0xb00) == 0) {
          iVar13 = 0;
          local_100 = 0;
        }
        else {
          iVar13 = __igc_xdp_run_prog(&local_a8);
          uVar20 = -iVar13;
          plVar8 = (long *)(long)(int)uVar20;
          if ((long *)0xfffffffffffff000 < plVar8) {
_L1892:
            if ((uVar20 & 0xfffffffd) == 0xfffffffc) {
              uVar21 = (uint)*(ushort *)((long)plVar32 + 0x14);
              local_f0 = (long)(int)(-uVar20 | (uint)local_f0);
              *(uint *)(plVar32 + 2) = (uint)uVar31 ^ *(uint *)(plVar32 + 2);
            }
            else if (-uVar20 == 1) {
              uVar2 = *(short *)((long)plVar32 + 0x14) + 1;
              uVar21 = (uint)uVar2;
              *(ushort *)((long)plVar32 + 0x14) = uVar2;
            }
            else {
              uVar21 = (uint)*(ushort *)((long)plVar32 + 0x14);
            }
            puVar16 = (ulong *)plVar32[1];
            uVar37 = (ulong)((int)uVar37 + 1);
            uVar19 = (int)lVar33 + uVar19;
            goto _L1901;
          }
          if (plVar8 != (long *)0x0) goto _L1891;
          local_100 = (long)local_a8 - (long)local_98;
          iVar13 = (int)local_100;
        }
        pvVar7 = local_a8;
        iVar36 = (int)local_a8;
        iVar5 = (int)local_a0 - iVar36;
        plVar15 = (long *)(long)iVar5;
        if (((ulong)pplVar39[5] >> 1 & 1) == 0) {
          plVar24 = pplVar39[5];
          plVar8 = (long *)__napi_alloc_skb(*pplVar39 + 9,(long)(iVar13 + 0x100),0xa20,lVar9);
          if (plVar8 == (long *)0x0) goto _L1903;
          if (lVar34 != 0) {
            *(long *)(plVar8[0x19] + (ulong)*(uint *)(plVar8 + 0x18) + 0x10) = lVar34;
          }
          plVar28 = plVar15;
          if ((long *)0x100 < plVar15) {
            iVar14 = eth_get_headlen(plVar8[2],pvVar7,0x100);
            plVar28 = (long *)(long)iVar14;
          }
          uVar20 = *(uint *)((long)plVar8 + 0xbc);
          iVar27 = (int)plVar28;
          iVar14 = iVar13 + iVar27;
          if (*(int *)((long)plVar8 + 0x74) != 0) goto _L2100;
          *(uint *)((long)plVar8 + 0xbc) = uVar20 + iVar14;
          *(int *)(plVar8 + 0xe) = iVar14 + *(int *)(plVar8 + 0xe);
          memcpy((void *)(plVar8[0x19] + (ulong)uVar20),local_98,(long)(iVar14 + 7) & 0xfffffff8);
          if (iVar13 != 0) {
            *(char *)(plVar8[0x19] + (ulong)*(uint *)(plVar8 + 0x18) + 1) = (char)local_100;
            iVar14 = *(int *)(plVar8 + 0xe);
            *(int *)(plVar8 + 0xe) = iVar14 - iVar13;
            if ((uint)(iVar14 - iVar13) < *(uint *)((long)plVar8 + 0x74)) goto _L2099;
            plVar8[0x1a] = (local_100 & 0xffffffff) + plVar8[0x1a];
          }
          puVar16 = (ulong *)plVar32[1];
          if (iVar5 == iVar27) {
            uVar2 = *(short *)((long)plVar32 + 0x14) + 1;
            uVar21 = (uint)uVar2;
            *(ushort *)((long)plVar32 + 0x14) = uVar2;
          }
          else {
            if (pgtable_l5_enabled == '\0') {
              if (pgtable_l4_enabled == '\0') {
                lVar33 = _kernel_map + -0x1000000000;
                lVar34 = 0x100000000;
              }
              else {
                lVar33 = _kernel_map + -0x200000000000;
                lVar34 = 0x20000000000;
              }
            }
            else {
              lVar33 = _kernel_map + -0x40000000000000;
              lVar34 = 0x4000000000000;
            }
            uVar20 = (uint)((ulong)(0x1000L << ((ulong)plVar24 & 1)) >> 1);
            skb_add_rx_frag(plVar8,0,(long)((iVar27 + iVar36) -
                                           ((int)(((long)puVar16 - (lVar33 - lVar34) >> 6) << 0xc) +
                                           (int)___napi_schedule)),(long)(int)uVar20);
            uVar21 = (uint)*(ushort *)((long)plVar32 + 0x14);
            puVar16 = (ulong *)plVar32[1];
            *(uint *)(plVar32 + 2) = *(uint *)(plVar32 + 2) ^ uVar20;
          }
        }
        else {
          uVar20 = (uint)((ulong)(0x1000L << ((ulong)pplVar39[5] & 1)) >> 1);
          plVar8 = (long *)napi_build_skb(local_90,(long)(int)uVar20);
          if (plVar8 == (long *)0x0) {
_L1903:
            pplVar39[0x12] = (long *)((long)pplVar39[0x12] + 1);
            *(short *)((long)plVar32 + 0x14) = *(short *)((long)plVar32 + 0x14) + 1;
            plVar8 = plVar28;
            break;
          }
          iVar36 = (int)local_a8 - (int)local_90;
          plVar8[0x1a] = plVar8[0x1a] + (long)iVar36;
          if (*(int *)((long)plVar8 + 0x74) != 0) goto _L2100;
          *(int *)((long)plVar8 + 0xbc) = iVar36 + iVar5 + *(int *)((long)plVar8 + 0xbc);
          *(int *)(plVar8 + 0xe) = *(int *)(plVar8 + 0xe) + iVar5;
          if (iVar13 != 0) {
            *(char *)(plVar8[0x19] + (ulong)*(uint *)(plVar8 + 0x18) + 1) = (char)local_100;
          }
          uVar21 = (uint)*(ushort *)((long)plVar32 + 0x14);
          puVar16 = (ulong *)plVar32[1];
          *(uint *)(plVar32 + 2) = *(uint *)(plVar32 + 2) ^ uVar20;
        }
      }
_L1901:
      if ((((long)*(int *)(&numa_node + *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8)
                          ) == *puVar16 >> 0x3e) && ((puVar16[1] & 2) == 0)) &&
         (iVar12 - uVar21 < 2)) {
        if (uVar21 == 1) {
          *(int *)((long)puVar16 + 0x34) = *(int *)((long)puVar16 + 0x34) + 0xfffe;
          *(undefined2 *)((long)plVar32 + 0x14) = 0xffff;
        }
        uVar2 = *(ushort *)((long)pplVar39 + 0x6c);
        uVar3 = uVar2 + 1;
        *(ushort *)((long)pplVar39 + 0x6c) =
             uVar3 & -(ushort)(uVar3 < *(ushort *)((long)pplVar39 + 0x44));
        plVar28 = pplVar39[3] + (ulong)uVar2 * 3;
        *plVar28 = *plVar32;
        plVar28[1] = plVar32[1];
        *(undefined4 *)(plVar28 + 2) = *(undefined4 *)(plVar32 + 2);
        *(undefined2 *)((long)plVar28 + 0x14) = *(undefined2 *)((long)plVar32 + 0x14);
      }
      else {
        dma_unmap_page_attrs(pplVar39[2],*plVar32,0x1000L << ((ulong)pplVar39[5] & 1),2,0x22);
        __page_frag_cache_drain(plVar32[1],*(undefined2 *)((long)plVar32 + 0x14));
      }
      plVar32[1] = 0;
      uVar10 = (long)((int)uVar10 + 1) & 0xffff;
      sVar18 = 0;
      if ((ulong)*(ushort *)(pplVar39 + 0xd) + 1 < (ulong)*(ushort *)((long)pplVar39 + 0x44)) {
        sVar18 = *(ushort *)(pplVar39 + 0xd) + 1;
      }
      *(short *)(pplVar39 + 0xd) = sVar18;
      if ((*(uint *)(plVar30 + 1) & 2) != 0) {
        lVar33 = igc_cleanup_headers(pplVar39,plVar30,plVar8);
        if (lVar33 == 0) {
          uVar19 = *(int *)(plVar8 + 0xe) + uVar19;
          igc_process_skb_fields(pplVar39,plVar30,plVar8);
          uVar37 = (ulong)((int)uVar37 + 1);
          napi_gro_receive(param_1,plVar8);
          plVar8 = (long *)0x0;
        }
        else {
          plVar8 = (long *)0x0;
        }
      }
      plVar28 = plVar8;
    } while (uVar37 < (ulong)(long)iVar29);
    if (local_f0 != 0) {
      igc_finalize_xdp(local_c0,local_f0);
    }
    uVar22 = uVar37 & 0xffffffff;
    uVar31 = (ulong)uVar19;
    iVar12 = (int)uVar37;
    uVar37 = (ulong)iVar12;
    goto _L1881;
  }
_L1812:
  uVar37 = 0;
  goto _L1809;
_L0:
  uVar10 = (ulong)uVar19;
  uVar22 = param_2;
  iVar12 = iVar29;
_L1855:
  *(short *)(pplVar39 + 0xd) = (short)uVar31;
joined_r0x001080b8:
  if (plVar30 < (long *)0x10) {
    bVar11 = 0;
  }
  else {
    bVar11 = igc_alloc_rx_buffers_zc(pplVar39,plVar30);
    bVar11 = bVar11 ^ 1;
  }
  if (local_d8 != 0) {
    igc_finalize_xdp(local_c0,local_d8);
  }
  lVar33 = param_1[-6];
  *(ulong *)(lVar33 + 0x70) = *(long *)(lVar33 + 0x70) + uVar22;
  *(ulong *)(lVar33 + 0x78) = *(long *)(lVar33 + 0x78) + uVar10;
  *(int *)((long)param_1 + -0x24) = *(int *)((long)param_1 + -0x24) + iVar12;
  *(uint *)(param_1 + -5) = *(int *)(param_1 + -5) + uVar19;
  lVar33 = xsk_uses_need_wakeup(pplVar39[0x28]);
  if (lVar33 == 0) {
    if (bVar11 != 0) {
      return param_2;
    }
  }
  else if ((bVar11 == 0) && (*(short *)(pplVar39 + 0xd) != *(short *)((long)pplVar39 + 0x6a))) {
    xsk_clear_rx_need_wakeup(pplVar39[0x28]);
  }
  else {
    xsk_set_rx_need_wakeup();
  }
  goto _L1877;
_L2100:
  ebreak();
  goto _L1930;
_L2099:
  ebreak();
  plVar8 = plVar28;
  param_1 = plVar15;
_L1966:
  uVar37 = 0;
  uVar31 = 0;
  uVar22 = 0;
  iVar12 = 0;
  uVar19 = 0;
_L1881:
  pplVar39[0x1c] = plVar8;
  lVar33 = param_1[-6];
  *(ulong *)(lVar33 + 0x70) = *(long *)(lVar33 + 0x70) + uVar22;
  *(ulong *)(lVar33 + 0x78) = *(long *)(lVar33 + 0x78) + uVar31;
  *(int *)((long)param_1 + -0x24) = *(int *)((long)param_1 + -0x24) + iVar12;
  *(uint *)(param_1 + -5) = *(int *)(param_1 + -5) + uVar19;
  if (uVar10 != 0) {
    igc_alloc_rx_buffers(pplVar39,uVar10);
  }
_L1877:
  if ((long)param_2 <= (long)uVar37) {
    return param_2;
  }
_L1852:
  if (local_e0 == 0) {
    return param_2;
  }
_L1809:
  lVar33 = napi_complete_done(param_1,uVar37);
  if (lVar33 == 0) goto _L1929;
  plVar30 = (long *)param_1[-6];
  uVar10 = param_1[-9];
  plVar15 = param_1;
  if (plVar30 == (long *)0x0) {
_L1930:
    uVar19 = *(uint *)(uVar10 + 0x13c);
    param_1 = plVar15;
  }
  else {
    uVar19 = *(uint *)(uVar10 + 0x138);
  }
  if ((uVar19 & 3) != 0) {
    uVar2 = *(ushort *)((long)param_1 + -0x34);
    sVar18 = *(short *)(uVar10 + 0x128);
    if (*(int *)(uVar10 + 0x44) == 1) {
      uVar19 = (uint)uVar2;
      if ((sVar18 == 10) || (sVar18 == 100)) {
_L1935:
        uVar20 = 0x3d4;
      }
      else {
        igc_update_itr_constprop_0(param_1 + -3);
        igc_update_itr_constprop_0(param_1 + -6);
        bVar11 = *(byte *)((long)param_1 + -0x1d);
        if (*(byte *)((long)param_1 + -0x1d) < *(byte *)((long)param_1 + -5)) {
          bVar11 = *(byte *)((long)param_1 + -5);
        }
        if (bVar11 == 0) {
          if (plVar30 == (long *)0x0) {
            uVar20 = 0x38;
            if (*(int *)(uVar10 + 0x13c) == 3) goto _L1976;
          }
          else {
            uVar20 = 0xc4;
            if (*(int *)(uVar10 + 0x138) != 3) {
              uVar20 = 0x38;
            }
          }
        }
        else {
          if (bVar11 != 1) {
            if (bVar11 != 2) goto _L1932;
            goto _L1935;
          }
_L1976:
          uVar20 = 0xc4;
        }
      }
      if (uVar19 != uVar20) {
        uVar21 = uVar20;
        if ((uVar19 < uVar20) &&
           (uVar21 = (uVar19 * uVar20) / ((uVar2 >> 2) + uVar20), uVar21 < uVar20)) {
          uVar21 = uVar20;
        }
        *(short *)((long)param_1 + -0x34) = (short)uVar21;
        *(undefined *)((long)param_1 + -0x32) = 1;
      }
    }
    else {
      if ((sVar18 == 10) || (sVar18 == 100)) {
        uVar19 = 0x3d4;
_L1944:
        if (uVar2 != uVar19) {
          *(short *)((long)param_1 + -0x34) = (short)uVar19;
          *(undefined *)((long)param_1 + -0x32) = 1;
        }
      }
      else {
        uVar19 = *(uint *)((long)param_1 + -0xc);
        if (*(uint *)((long)param_1 + -0x24) == 0) {
          uVar20 = 0;
          if (uVar19 != 0) {
_L1946:
            uVar21 = *(uint *)(param_1 + -2) / uVar19;
            if (*(uint *)(param_1 + -2) / uVar19 < uVar20) {
              uVar21 = uVar20;
            }
            goto _L1948;
          }
        }
        else {
          uVar20 = *(uint *)(param_1 + -5) / *(uint *)((long)param_1 + -0x24);
          uVar21 = uVar20;
          if (uVar19 != 0) goto _L1946;
_L1948:
          if (uVar21 != 0) {
            iVar12 = uVar21 + 0x18;
            if (3000 < iVar12) {
              iVar12 = 3000;
            }
            if (iVar12 - 0x12dU < 899) {
              uVar19 = iVar12 / 3;
            }
            else {
              uVar19 = iVar12 / 2;
            }
            if ((int)uVar19 < 0xc4) {
              if (plVar30 == (long *)0x0) {
                iVar12 = *(int *)(uVar10 + 0x13c);
              }
              else {
                iVar12 = *(int *)(uVar10 + 0x138);
              }
              if (iVar12 == 3) {
                uVar19 = 0xc4;
              }
            }
            goto _L1944;
          }
        }
      }
      param_1[-5] = 0;
      param_1[-2] = 0;
    }
  }
_L1932:
  if ((*(ulong *)(uVar10 + 0x38) >> 2 & 1) == 0) {
    if (*(long *)(uVar10 + 0x48) == 0) {
      igc_irq_enable(uVar10);
    }
    else if (*(long *)(uVar10 + 0x2a0) != 0) {
      fence();
      *(undefined4 *)(*(long *)(uVar10 + 0x2a0) + 0x1524) = *(undefined4 *)(param_1 + -7);
      if (*(short *)(&__mmiowb_state + *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8))
          != 0) {
        *(short *)(&DAT_0011c232 + *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8)) =
             *(short *)(&__mmiowb_state +
                       *(long *)(&__per_cpu_offset + (long)*(int *)(tp + 0x20) * 8));
      }
    }
  }
_L1929:
  iVar29 = iVar29 + -1;
  if ((long)uVar37 < (long)iVar29) {
    iVar29 = (int)uVar37;
  }
  return (long)iVar29;
}

