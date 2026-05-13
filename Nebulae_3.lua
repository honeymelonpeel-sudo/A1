--[[
  Nebulae Gen15 标准版 Beta 6.2
  架构升级：
    [修复] _maybe_check() vCHKC赋值缺失'=' — 修复unexpected symbol near '='
    [新增] 非load路径 — 4种执行路径(dofile/loadstring/chunk)，不依赖load
    [核心] VM池化动态轮换 — 8VM统一调度池，运行时环境熵重新分配真假角色；
           真VM可变为假，假VM可变为真，角色每次执行均可不同
    [核心] 角色翻转 — 运行时随机翻转真假VM执行顺序
    [核心] 执行模式动态选择 — 4种执行路径每次运行随机选择
    [核心] Lua解释器完整性检测 — 验证C函数行为/版本一致性；
           检测解释器级内存patch、函数hook
    [核心] 技术深度隐藏 — 所有防护调用经间接跳转表；
           检测/防护标识符经多层编码；移除可模式匹配防护特征
    [核心] 完整VM-load路径 — payload严格经VM内__call元表load()执行
           + 可选非load路径
  + 保留Beta 6.1全部特性
  兼容：Lua 5.1/5.2/5.3/5.4/5.5/LuaJIT/Luau(Roblox)
  警告：任何员工不可泄露源码
]]

local CONFIG = {
    FRAG_COUNT            = 100,
    BATCH_SIZE            = 10,
    FEISTEL_ROUNDS        = 3,
    JUNK_INST_COUNT       = 2000,
    VAR_NAME_MIN          = 60,
    VAR_NAME_MAX          = 90,
    SLIDE_WINDOW          = 5,
    REMAP_PERIOD_MIN      = 8,
    REMAP_PERIOD_MAX      = 20,
    HANDLER_SAMPLE_PERIOD = 5,
    CHECK_INTERVAL_MIN    = 3,
    CHECK_INTERVAL_MAX    = 9,
    ENTROPY_WINDOW        = 4,
    REAL_VM_COUNT         = 3,
    FAKE_VM_COUNT         = 5,
    TOTAL_VM_SLOTS        = 8,
    DECOY_STMTS_MIN       = 6,
    DECOY_STMTS_MAX       = 18,
    ENABLE_FEISTEL               = true,
    ENABLE_CTX_LINK              = true,
    ENABLE_CFF                   = true,
    ENABLE_FAKE_VM               = true,
    ENABLE_SELF_MODIFY           = true,
    ENABLE_EXEC_DETECT           = true,
    ENABLE_CORO_TIMING           = true,
    ENABLE_BEHAVIORAL_FINGERPRINT= true,
    ENABLE_ENTROPY_TREND         = true,
    ENABLE_MULTI_CLOCK           = true,
    ENABLE_SV_INTEGRITY          = true,
    ENABLE_FUNC_HASH             = true,
    ENABLE_MEMORY_WIPE           = true,
    ENABLE_NATIVE_GUARD          = true,
    ENABLE_GLOBAL_REPLACE_GUARD  = true,
    ENABLE_INTEGRITY_HASH        = true,
    ENABLE_ENV_SPOOFING          = true,
    ENABLE_INTERP_CHECK          = true,
    EXEC_DETECT_MODE      = "corrupt",
    KEY_SALT        = "--[[ Nebulae Gen15 Beta6.2 Apex. System Integrity Verified. ]]",
    INNER_KEY_SALT  = "INNER_LAYER_GEN15_B62_SALT_9z3x",
    OUTPUT_PREFIX   = "Nebulae_",
}

local _mr  = math.random
local _tc  = table.concat
local _sb  = string.byte
local _ss  = string.sub
local _mf  = math.floor
local _rem = table.remove
local _sc  = string.char

local function _mk_seed()
    local t = (os and os.time  and os.time())  or 0
    local c = (os and os.clock and os.clock()) or 0
    local a = tostring({}):match("0x(%x+)") or "0"
    local n = tonumber(a, 16) or 0
    return _mf(t * 1000 + c * 999983 + n % 999999)
end
math.randomseed(_mk_seed())

local _vc = 0
local function _RV()
    _vc = _vc + 1
    local p = {"_lI","_Il","_iI","_1l","_Ii","_lL","_Li","_ll","_II","_LL","_0O","_O0","_oO","_l1I"}
    local c = "Il1iIli1liIlLOo0O"
    local len = _mr(CONFIG.VAR_NAME_MIN, CONFIG.VAR_NAME_MAX)
    local res = {"_Nebulae_", p[_mr(1,#p)], _vc, "_"}
    for i = 1, len do
        local idx = _mr(1, #c)
        res[#res+1] = _ss(c, idx, idx)
    end
    return _tc(res)
end

local function _XOR(a, b)
    local r, m = 0, 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then r = r + m end
        a, b, m = _mf(a/2), _mf(b/2), m * 2
    end
    return r
end

local function _KSA(ki, mx)
    local S = {}
    for i = 0, 255 do S[i] = i end
    local kb = {}
    local k = ki
    kb[0]=k%256; k=_mf(k/256); kb[1]=k%256; k=_mf(k/256)
    kb[2]=k%256; k=_mf(k/256); kb[3]=k%256
    local m = mx or 0
    kb[4]=m%256; m=_mf(m/256); kb[5]=m%256; m=_mf(m/256)
    kb[6]=m%256; m=_mf(m/256); kb[7]=m%256
    local j = 0
    for i = 0, 255 do
        j = (j + S[i] + kb[i%8]) % 256
        S[i], S[j] = S[j], S[i]
    end
    return S
end

local function _RC4(s, ki, mx)
    local S = _KSA(ki, mx or 0)
    local ii, j = 0, 0
    local out = {}
    for n = 1, #s do
        ii = (ii+1)%256; j = (j+S[ii])%256
        S[ii], S[j] = S[j], S[ii]
        out[n] = _XOR(_sb(s,n), S[(S[ii]+S[j])%256])
    end
    return out
end

local function _RC4_arr(arr, ki, mx)
    local S = _KSA(ki, mx or 0)
    local ii, j = 0, 0
    local out = {}
    for n = 1, #arr do
        ii = (ii+1)%256; j = (j+S[ii])%256
        S[ii], S[j] = S[j], S[ii]
        out[n] = _XOR(arr[n], S[(S[ii]+S[j])%256])
    end
    return out
end

local function _FEISTEL_ENC(arr, key, rounds)
    rounds = rounds or CONFIG.FEISTEL_ROUNDS
    local n = #arr; if n < 1 then return arr end
    local res = {}; for i=1,n do res[i]=arr[i] end
    for r = 1, rounds do
        local prev = _XOR(key%256, r*97%256); local tmp = {}
        for i = 1, n do
            local carry = (prev*131 + r*83 + i*17) % 256
            tmp[i] = _XOR(res[i], carry); prev = res[i]
        end; res = tmp
    end
    return res
end

local function _FEISTEL_DEC(arr, key, rounds)
    rounds = rounds or CONFIG.FEISTEL_ROUNDS
    local n = #arr; if n < 1 then return arr end
    local res = {}; for i=1,n do res[i]=arr[i] end
    for r = rounds, 1, -1 do
        local prev = _XOR(key%256, r*97%256); local tmp = {}
        for i = 1, n do
            local carry = (prev*131 + r*83 + i*17) % 256
            local orig = _XOR(res[i], carry); prev = orig; tmp[i] = orig
        end; res = tmp
    end
    return res
end

local function _A2L(arr)
    local r = {}
    for i = 1, #arr do r[i] = tostring(arr[i]) end
    return "{" .. _tc(r, ",") .. "}"
end

local function _DERIVE_KEY(s)
    local h = 0
    for i = 1, #s do h = (h*167 + _sb(s,i)) % 65536 end
    return (h < 100 and h+100 or h)
end

local function _FRAG_MIX(idx, seed) return (idx*7919 + seed*31) % 65536 end

local function _RVM_KEYHASH(k)
    local h, tmp = 0, k
    for _ = 1, 4 do
        h = (h*167 + tmp%256) % 65536
        tmp = _mf(tmp / 256)
    end
    return h
end

local _SD_NAME = nil
local function _SE(s)
    local key = _mr(1, 200); local b = {}
    for i = 1, #s do b[i] = tostring((_sb(s,i) + key) % 256) end
    return _SD_NAME .. "({" .. _tc(b,",") .. "}," .. key .. ")"
end
local function _SD_SRC(fn)
    return "local function " .. fn ..
        "(b,k) local r={} for i=1,#b do r[i]=string.char((b[i]-k+256)%256) end return table.concat(r) end"
end

local _DV_POOL = {"_dv","_dc","_dm","_dn","_dp","_dq","_dr","_ds","_dt","_du","_dw"}
local _DV_OPS  = {"+", "-", "*", "%"}

local function _gen_decoy_source()
    local lines = {}
    local nvars = {}
    local ndecl = _mr(CONFIG.DECOY_STMTS_MIN, _mf(CONFIG.DECOY_STMTS_MAX/2))
    for i = 1, ndecl do
        local vn = _DV_POOL[_mr(1,#_DV_POOL)] .. "_" .. _mr(10,999)
        nvars[i] = vn
        lines[#lines+1] = "local " .. vn .. "=" .. _mr(1,99999)
    end
    if #nvars < 2 then
        nvars[#nvars+1] = "_dv_x"; lines[#lines+1] = "local _dv_x=" .. _mr(1,9999)
        nvars[#nvars+1] = "_dv_y"; lines[#lines+1] = "local _dv_y=" .. _mr(1,9999)
    end
    for _ = 1, _mr(2,6) do
        local dst  = nvars[_mr(1,#nvars)]
        local src1 = nvars[_mr(1,#nvars)]
        local op   = _DV_OPS[_mr(1,#_DV_OPS)]
        local imm  = _mr(1,255)
        lines[#lines+1] = dst .. "=" .. src1 .. op .. imm
    end
    local acc = nvars[_mr(1,#nvars)]
    local lim = _mr(4,20)
    local step = _mr(1,5)
    lines[#lines+1] = "local _dv_sum_=0"
    lines[#lines+1] = "for _dv_i_=1," .. lim .. " do"
    lines[#lines+1] = "_dv_sum_=(_dv_sum_+" .. acc .. "*_dv_i_+" .. step .. ")%65536"
    lines[#lines+1] = "end"
    lines[#lines+1] = "local _dv_s_=tostring(_dv_sum_)"
    lines[#lines+1] = "if type(_dv_s_)~=" .. '"string"' .. " then _dv_s_=" .. '"?"' .. " end"
    lines[#lines+1] = "return _dv_s_"
    return _tc(lines, "\n")
end

local VM  = {}
local FVM = {}

local function _assign_vm()
    local pool = {}
    for i = 1, 255 do pool[i] = i end
    local function pick()
        local idx = _mr(1,#pool); local v = pool[idx]; _rem(pool,idx); return v
    end
    VM.LDK=pick(); VM.LDR=pick(); VM.STM=pick(); VM.LDM=pick()
    VM.PSH=pick(); VM.POP=pick(); VM.ADD=pick(); VM.SUB=pick()
    VM.MUL=pick(); VM.DIV=pick(); VM.MOD=pick(); VM.XOR=pick()
    VM.AND=pick(); VM.INC=pick(); VM.DEC=pick(); VM.NEG=pick()
    VM.EQ =pick(); VM.NEQ=pick(); VM.LT =pick(); VM.LE =pick()
    VM.NOT=pick(); VM.JMP=pick(); VM.JZ =pick(); VM.JNZ=pick()
    VM.CAL=pick(); VM.NOP=pick(); VM.HLT=pick()
    VM.ADDK=pick(); VM.XORK=pick(); VM.MODK=pick(); VM.FUSE_AS=pick()
    FVM.F_MOV=pick();  FVM.F_ADD=pick();  FVM.F_CMP=pick()
    FVM.F_JMP=pick();  FVM.F_CALL=pick(); FVM.F_PUSH=pick()
    FVM.F_POP=pick();  FVM.F_RET=pick();  FVM.F_NOP=pick()
    FVM.F_XOR=pick();  FVM.F_AND=pick();  FVM.F_HLT=pick()
    FVM.F_TRIG=pick()
end

local OP = {
    LOAD_CONST   = 1,
    LOAD_REG     = 2,
    STORE_MEM    = 3,
    LOAD_MEM     = 4,
    ADD_RR       = 5,
    SUB_RR       = 6,
    MUL_RR       = 7,
    DIV_RR       = 8,
    MOD_RR       = 9,
    XOR_RR       = 10,
    AND_RR       = 11,
    NOT_R        = 12,
    NEG_R        = 13,
    INC_R        = 14,
    DEC_R        = 15,
    CMP_EQ       = 16,
    CMP_NE       = 17,
    CMP_LT       = 18,
    CMP_LE       = 19,
    JMP          = 20,
    JZ           = 21,
    JNZ          = 22,
    CALL_NATIVE  = 23,
    PUSH         = 24,
    POP          = 25,
    NOP          = 26,
    HLT          = 27,
    ADD_RC       = 28,
    XOR_RC       = 29,
    MOD_RC       = 30,
    FUSE_ADC_STM = 31,
}
local INSTR_WIDTH = 5

local function _encode_instr(op, a, b, c, d)
    return {op, a or 0, b or 0, c or 0, d or 0}
end

local function _instrs_to_bytes(instrs)
    local out = {}
    for _, instr in ipairs(instrs) do
        for j = 1, INSTR_WIDTH do out[#out+1] = instr[j] or 0 end
    end
    return out
end

local function _encrypt_bytecode(bytes, base_key, poly_seed, feistel_rounds)
    local n = #bytes
    local CTX = _XOR(poly_seed%65536, base_key%65536)
    local enc = {}
    local i, idx = 1, 0
    while i <= n do
        idx = idx + 1
        local chunk = {}
        for j = 0, INSTR_WIDTH-1 do chunk[j+1] = bytes[i+j] or 0 end
        local fkey = _XOR(base_key%65536, CTX%65536)
        local mix  = _FRAG_MIX(idx, poly_seed)
        local after_rc4 = _RC4_arr(chunk, fkey, mix)
        local after_fst = CONFIG.ENABLE_FEISTEL
            and _FEISTEL_ENC(after_rc4, CTX%256, feistel_rounds)
            or  after_rc4
        for j = 1, INSTR_WIDTH do enc[#enc+1] = after_fst[j] end
        local last = after_fst[INSTR_WIDTH] or 0
        CTX = (CTX*31 + last) % 65536
        i = i + INSTR_WIDTH
    end
    return enc, CTX
end

local function _build_payload_bytecode(consts_out)
    local function KC(v) consts_out[#consts_out+1]=v; return #consts_out end
    local instrs = {}
    local function PI(...) instrs[#instrs+1] = _encode_instr(...) end

    local kZERO    = KC(0)
    local kONE     = KC(1)
    local kNID_INIT= KC(_mr(10000,99999))
    local kNID_EXEC= KC(_mr(100000,999999))
    local kNID_CHK = KC(_mr(1000,9999))

    PI(OP.CALL_NATIVE, kNID_INIT)
    PI(OP.CALL_NATIVE, kNID_CHK)
    local kSEED = KC(_mr(100,999))
    PI(OP.LOAD_CONST, 0, kSEED)
    PI(OP.LOAD_CONST, 1, KC(_mr(100,999)))
    PI(OP.ADD_RC, 2, 0, kONE)
    PI(OP.MUL_RR, 3, 0, 2)
    PI(OP.MOD_RC, 4, 3, KC(2))
    PI(OP.CMP_EQ, 5, 4, kZERO)
    local dead_target_pos = #instrs + 3
    PI(OP.JZ,  5, KC(dead_target_pos+2))
    PI(OP.CALL_NATIVE, kNID_EXEC)
    PI(OP.HLT)
    PI(OP.LOAD_CONST, 7, KC(_mr(1,255)))
    PI(OP.NOP)
    PI(OP.HLT)

    return instrs,
           kNID_INIT, kNID_EXEC, kNID_CHK,
           consts_out[kNID_INIT], consts_out[kNID_EXEC], consts_out[kNID_CHK]
end

function build(source_code)
    _assign_vm()
    _vc = 0

    local BASE_KEY   = _DERIVE_KEY(CONFIG.KEY_SALT)
    local IK         = _DERIVE_KEY(CONFIG.KEY_SALT .. CONFIG.INNER_KEY_SALT)
    local POLY_SEED  = _mr(100000, 999999)
    local RT_CHECK   = _mr(10000,  99999)
    local FC         = CONFIG.FRAG_COUNT
    local BS         = CONFIG.BATCH_SIZE
    local FLR        = CONFIG.FEISTEL_ROUNDS
    local SW         = CONFIG.SLIDE_WINDOW
    local REMAP_MIN  = CONFIG.REMAP_PERIOD_MIN
    local REMAP_RNG  = CONFIG.REMAP_PERIOD_MAX - REMAP_MIN + 1
    local CHK_MIN    = CONFIG.CHECK_INTERVAL_MIN
    local CHK_RNG    = CONFIG.CHECK_INTERVAL_MAX - CHK_MIN + 1
    local ENT_WIN    = CONFIG.ENTROPY_WINDOW
    local BEH_SENT   = _mr(10000000, 99999999)
    local INIT_REMAP = _mr(REMAP_MIN, CONFIG.REMAP_PERIOD_MAX)

    local SK_A = _mr(10000, 99999)
    local SK_B = _mr(10000, 99999)
    local SK_C = _mr(10000, 99999)

    local CTX = _XOR(POLY_SEED%65536, IK%65536)
    local src_len = #source_code
    local fsz = _mf(math.max(src_len,1)/FC); if fsz < 1 then fsz = 1 end
    local enc_frags = {}
    for i = 1, FC do
        local s = (i-1)*fsz+1
        local e = (i==FC) and src_len or math.min(i*fsz, src_len)
        local piece = (s <= src_len) and _ss(source_code, s, e) or ""
        local fkey = _XOR(BASE_KEY%65536, CTX%65536)
        local mix  = _FRAG_MIX(i, POLY_SEED)
        local r    = _RC4(piece, fkey, mix)
        local f    = CONFIG.ENABLE_FEISTEL and _FEISTEL_ENC(r, CTX%256, FLR) or r
        enc_frags[i] = f
        CTX = (CTX*31 + (f[#f] or 0)) % 65536
    end

    local payload_consts = {}
    local payload_instrs,
          kNID_INIT_idx, kNID_EXEC_idx, kNID_CHK_idx,
          NID_INIT, NID_EXEC, NID_CHK
          = _build_payload_bytecode(payload_consts)

    local payload_raw_bytes = _instrs_to_bytes(payload_instrs)

    -- ================================================================
    -- [NEW] 8-slot VM 池化：统一密钥池，REAL_SLOT_IDX 为运行时环境熵选出
    -- 所有8个槽都加密相同payload，密钥不同；运行时环境熵决定哪个槽的密钥正确
    -- ================================================================
    local TOTAL_SLOTS = CONFIG.TOTAL_VM_SLOTS
    local REAL_SLOT_IDX = _mr(1, TOTAL_SLOTS)

    local VM_KEYS    = {}
    local VM_OFFSETS = {}
    for si = 1, TOTAL_SLOTS do
        local off = (si == REAL_SLOT_IDX) and 0 or _mr(10000, 99999)
        VM_OFFSETS[si] = off
        local k = (BASE_KEY + off) % 65536
        if k < 100 then k = k + 100 end
        VM_KEYS[si] = k
    end

    local RVM_EHASH = _RVM_KEYHASH(BASE_KEY)

    local vm_enc_bytes = {}
    for si = 1, TOTAL_SLOTS do
        local enc, _ = _encrypt_bytecode(payload_raw_bytes, VM_KEYS[si], POLY_SEED, FLR)
        vm_enc_bytes[si] = enc
    end

    -- ================================================================
    -- 保留5个伪VM用于诱饵执行（load()诱饵，暴露给分析者）
    -- ================================================================
    local FAKE_KEYS    = {}
    local FAKE_POLYS   = {}
    local fake_enc_data = {}

    for fi = 1, CONFIG.FAKE_VM_COUNT do
        local fkey  = _mr(1000, 60000)
        local fpoly = _mr(100000, 999999)
        FAKE_KEYS[fi]  = fkey
        FAKE_POLYS[fi] = fpoly
        local decoy_src = _gen_decoy_source()
        local r   = _RC4(decoy_src, fkey, fpoly)
        local enc = CONFIG.ENABLE_FEISTEL and _FEISTEL_ENC(r, fkey%256, FLR) or r
        fake_enc_data[fi] = enc
    end

    -- 变量名生成
    local used = {}
    local function NV()
        local n; repeat n = _RV() until not used[n]; used[n] = true; return n
    end
    local V = {}; for i = 1, 1400 do V[i] = NV() end
    _SD_NAME = NV()

    local vSD=_SD_NAME;  local vCAP=V[1];   local vCLK=V[2];   local vSV=V[3]
    local vTM=V[4];      local vHCC=V[5];   local vIH=V[6];    local vSDB=V[7]
    local vFR=V[9];      local vEI=V[10];   local vIE=V[11]
    local vCH=V[12];     local vNG=V[13];   local vIC=V[14];   local vSC2=V[15]
    local vSG=V[17];     local vAH=V[18];   local vTRP=V[19]
    local vPS=V[20];     local vRLD=V[21];  local vBK=V[22];   local vIK2=V[23]
    local vRTC=V[24];    local vBAS=V[25];  local vTHR=V[26];  local vXOR=V[27]
    local vKSA=V[28];    local vR4D=V[29];  local vFMX=V[30]
    local vVMR=V[31];    local vVMK=V[32];  local vVMP=V[33];  local vVMN=V[34]
    local vVMF=V[35];    local vVMDT=V[36]
    local vADH=V[37];    local vSTK=V[39];  local vSEL=V[40];  local vPOI=V[41]
    local vMCK=V[42];    local vSVI=V[43];  local vFH=V[44];   local vFHC=V[45]
    local vFED=V[47];    local vEXD=V[60];  local vCRT=V[61];  local vCS=V[62]
    local vUPVK=V[63]
    local vPCRG=V[70];   local vPCLD=V[71]; local vPCPC=V[72]; local vPCOC=V[73]
    local vPCSD=V[74];   local vPCDB=V[75]; local vPCTK=V[76]; local vBSNT=V[77]
    local vBEHC=V[78];   local vBEH0=V[79]; local vUPBC=V[80]
    local vHSH=V[81];    local vHSC=V[82]
    local vSKEY=V[100]
    local vBFPR=V[101]
    local vCFFM=V[102]
    local vRMTB=V[94];   local vRMCD=V[95]
    local vSLWD=V[96];   local vSLK=V[97]
    local vCHKC=V[98];   local vENTB=V[99]
    local vVMCK_v=V[110]
    local vVMEX=V[111]
    local vFKVM={}
    local vFDATA={}
    local vVMPOOL={}     -- [NEW] 统一VM池数组变量
    local vVMKEYS=V[120]
    local vRVMEH=V[121]
    local vPEXEC=V[123]
    local vHLDTBL=V[124]
    local vHLDIDX=V[125]
    local vENVOFF=V[126] -- [NEW] 运行时环境偏移
    local vEXEM=V[129]  -- [NEW] 执行模式索引
    local vDISP=V[127]   -- [NEW] 间接跳转表
    local vINTRP=V[128]  -- [NEW] 解释器检测函数
    for si = 1, TOTAL_SLOTS do vVMPOOL[si] = V[130+si] end
    for fi = 1, CONFIG.FAKE_VM_COUNT do
        vFKVM[fi] = V[145+fi]
        vFDATA[fi] = V[155+fi]
    end

    local body = {}
    local function E(s) body[#body+1] = s end

    -- ================================================================
    -- 预捕获块
    -- ================================================================
    E("local " .. vPCRG .. "=rawget")
    E("local _GR=_G or (type(getfenv)=='function' and getfenv(0)) or {}")
    E("local " .. vPCLD .. "=" .. vPCRG .. "(_GR," .. _SE("load") ..
        ") or " .. vPCRG .. "(_GR," .. _SE("loadstring") .. ") or load or loadstring")
    E("local " .. vPCPC .. "=" .. vPCRG .. "(_GR," .. _SE("pcall") .. ") or pcall")
    E("local _PC_os_t=" .. vPCRG .. "(_GR," .. _SE("os") .. ")")
    E("local " .. vPCOC .. "=(_PC_os_t and type(_PC_os_t)=='table' and " ..
        vPCRG .. "(_PC_os_t," .. _SE("clock") .. ")) or nil")
    E("local " .. vPCTK .. "=type(tick)=='function' and " ..
        vPCRG .. "(_GR," .. _SE("tick") .. ") or nil")
    E("if not " .. vPCOC .. " then " ..
        vPCOC .. "=" .. vPCTK .. " or function() return 0 end end")
    E("local _PC_str_t=" .. vPCRG .. "(_GR," .. _SE("string") .. ")")
    E("local " .. vPCSD .. "=(_PC_str_t and " ..
        vPCRG .. "(_PC_str_t," .. _SE("dump") .. ")) or nil")
    E("local " .. vPCDB .. "=" .. vPCRG .. "(_GR," .. _SE("debug") .. ")")
    E("if not " .. vPCDB .. " and type(debug)=='table' then " .. vPCDB .. "=debug end")

    E("if " .. vPCSD .. " then")
    E("  local _ok1=" .. vPCPC .. "(" .. vPCSD .. "," .. vPCLD .. ")")
    E("  if _ok1 then error(" .. _SE("IMMUNE:load-lua-wrapped") .. ") end")
    E("  local _ok2=" .. vPCPC .. "(" .. vPCSD .. "," .. vPCPC .. ")")
    E("  if _ok2 then error(" .. _SE("IMMUNE:pcall-lua-wrapped") .. ") end")
    E("end")

    local hld_idx_val = _mr(100000, 999999)
    E("local " .. vHLDTBL .. "=setmetatable({},{})")
    E("local " .. vHLDIDX .. "=" .. hld_idx_val)
    E("rawset(" .. vHLDTBL .. "," .. vHLDIDX .. "," .. vPCLD .. ")")

    E("local " .. vBSNT .. "=" .. BEH_SENT)
    E("local function " .. vBEHC .. "() return " .. vBSNT .. " end")
    E("local function " .. vBEH0 .. "() return " .. RT_CHECK .. " end")

    E("local " .. vSKEY .. "=(function()")
    E("  local _t=type(" .. vPCOC .. ")=='function' and " .. vPCOC .. "() or 0")
    E("  local _tf=(_t-math.floor(_t))*1000000")
    E("  local _pc_addr=tostring(" .. vPCPC .. "):match('0x(%x+)') or '0'")
    E("  local _pa=tonumber(_pc_addr,16) or 0")
    E("  local _mix=(" .. SK_A .. "*math.floor(_tf+0.5)+" ..
        SK_B .. "*(_pa%65536)+" .. SK_C .. ")%65536")
    E("  if _mix<100 then _mix=_mix+100 end")
    E("  return _mix")
    E("end)()")

    -- [NEW] 运行时环境偏移：决定VM池中哪个槽真正执行payload
    -- 偏移由环境因素决定，debug/hook环境偏移会不同导致错误槽执行
    local ENV_OFF_SCALE = _mr(1, TOTAL_SLOTS-1)
    E("local " .. vENVOFF .. "=(function()")
    E("  local _oc=" .. vPCOC .. "()")
    E("  local _tf=math.floor((_oc-math.floor(_oc))*1e7)%" .. TOTAL_SLOTS)
    E("  local _pa=tonumber((tostring(" .. vPCPC ..
        "):match('0x(%x+)') or '0'),16) or 0")
    E("  local _pa2=tonumber((tostring(rawget):match('0x(%x+)') or '0'),16) or 0")
    E("  local _base=(_pa%3+_pa2%3+_tf%" .. TOTAL_SLOTS .. ")%" .. TOTAL_SLOTS)
    E("  return _base")
    E("end)()")
    -- [NEW] 执行模式：每次运行基于运行时熵选择不同执行路径
    E("local " .. vEXEM .. "=(function()")
    E("  local _oc=" .. vPCOC .. "()")
    E("  local _tf=math.floor((_oc-math.floor(_oc))*1e9)%4")
    E("  local _pa=tonumber((tostring(math):match('0x(%x+)') or '0'),16) or 0")
    E("  return (_pa%3+_tf)%4")
    E("end)()")

    E(_SD_SRC(vSD))
    E("local _LST=" .. vPCLD)

    -- ================================================================
    -- 能力检测
    -- ================================================================
    E("local " .. vCAP .. "=(function()")
    E("  local c={}")
    E("  c.is_roblox=(type(game)=='userdata' and type(warn)=='function')")
    E("  c.is_luau=c.is_roblox or type(buffer)=='table' or type(task)=='table'")
    E("  c.has_sfe=type(setfenv)=='function'")
    E("  local _db=" .. vPCDB .. " or (type(debug)=='table' and debug) or nil")
    E("  c.has_db=_db~=nil")
    E("  c.has_dgi=c.has_db and type(_db.getinfo)=='function'")
    E("  c.has_dgh=c.has_db and type(_db.gethook)=='function'")
    E("  c.has_dsh=c.has_db and type(_db.sethook)=='function'")
    E("  c.has_dgu=c.has_db and type(_db.getupvalue)=='function'")
    E("  c.has_sd=" .. vPCSD .. "~=nil")
    E("  c.has_load4=false")
    E("  if type(" .. vPCLD .. ")=='function' then")
    E("    local ok=" .. vPCPC .. "(function() " .. vPCLD ..
        "(" .. _SE("return 1") .. "," .. _SE("=t") .. "," .. _SE("t") .. ",{}) end)")
    E("    c.has_load4=ok")
    E("  end")
    E("  c.native_what=" .. _SE("C"))
    E("  if c.has_dgi then " .. vPCPC .. "(function()")
    E("    local i=_db.getinfo(" .. vPCPC .. "," .. _SE("S") .. ")")
    E("    if i then c.native_what=i.what end")
    E("  end) end")
    E("  c.has_oc=" .. vPCOC .. "~=nil")
    E("  c.has_tick=" .. vPCTK .. "~=nil")
    E("  c.db_count=0")
    E("  if c.has_db and _db then for _ in pairs(_db) do c.db_count=c.db_count+1 end end")
    E("  c.db_ref=_db")
    E("  return c")
    E("end)()")

    E("local " .. vCLK .. "=" .. vPCOC)

    E("local _LIV")
    E("if " .. vCAP .. ".is_luau then")
    E("  if " .. vCAP .. ".has_load4 then")
    E("    _LIV=function(s,e) return " .. vPCLD ..
        "(s," .. _SE("=n") .. "," .. _SE("t") .. ",e) end")
    E("  elseif " .. vCAP .. ".has_sfe then")
    E("    _LIV=function(s,e) local f,r=" .. vPCLD .. "(s) if f and e then setfenv(f,e) end return f,r end")
    E("  else _LIV=function(s) return " .. vPCLD .. "(s) end end")
    E("elseif " .. vCAP .. ".has_load4 then")
    E("  _LIV=function(s,e) return " .. vPCLD .. "(s," ..
        _SE("=n") .. "," .. _SE("bt") .. ",e) end")
    E("elseif " .. vCAP .. ".has_sfe then")
    E("  _LIV=function(s,e) local f,r=" .. vPCLD ..
        "(s) if f and e then setfenv(f,e) end return f,r end")
    E("else _LIV=function(s) return " .. vPCLD .. "(s) end end")

    E("local " .. vSV .. "=(function()")
    E("  return {G=_GR,rg=" .. vPCRG .. ",rw=rawset,pc=" .. vPCPC ..
        ",er=error,sm=setmetatable,ip=ipairs,")
    E("    tbl=table,str=string,mth=math,db=(" .. vPCDB .. " or {}),")
    E("    os=(_PC_os_t or {}),ld=" .. vPCLD .. ",sd=" .. vPCSD .. ",")
    E("    up=(table.unpack or unpack),tc=table.concat,sc=string.char,")
    E("    sb=string.byte,mf=math.floor,oc=" .. vCLK .. ",")
    E("    sfe=(type(setfenv)=='function' and setfenv or nil),")
    E("    cc=(type(collectgarbage)=='function' and collectgarbage or function() end)}")
    E("end)()")

    E("local " .. vBK  .. "=" .. BASE_KEY)
    E("local " .. vIK2 .. "=" .. IK)
    E("local " .. vPS  .. "=" .. POLY_SEED)
    E("local " .. vRTC .. "=" .. RT_CHECK)
    E("local " .. vTM  .. "=0")
    E("local " .. vHCC .. "=0")
    E("local " .. vIH  .. "=0")
    E("local " .. vFH  .. "=0")
    E("local " .. vSDB .. "=" .. vSV .. ".db")

    E("local " .. vBAS .. " local " .. vTHR)
    E("do local t0=" .. vCLK .. "() local s=0")
    E("  for i=1,200 do s=s+i end")
    E("  " .. vBAS .. "=" .. vCLK .. "()-t0")
    E("  " .. vTHR .. "=" .. vBAS .. "*1000/200*5")
    E("  if " .. vTHR .. "<0.1 then " .. vTHR .. "=0.1 end")
    E("  if " .. vTHR .. ">0.5 then " .. vTHR .. "=0.5 end")
    E("end")

    E("local function " .. vXOR .. "(a,b)")
    E("  local r,m=0,1")
    E("  while a>0 or b>0 do")
    E("    if a%2~=b%2 then r=r+m end")
    E("    a,b,m=" .. vSV .. ".mf(a/2)," .. vSV .. ".mf(b/2),m*2")
    E("  end return r")
    E("end")

    E("local function " .. vKSA .. "(ki,mx)")
    E("  local S={} for i=0,255 do S[i]=i end")
    E("  local kb={} local k=ki")
    E("  kb[0]=k%256 k=" .. vSV .. ".mf(k/256) kb[1]=k%256 k=" ..
        vSV .. ".mf(k/256)")
    E("  kb[2]=k%256 k=" .. vSV .. ".mf(k/256) kb[3]=k%256")
    E("  local m=mx or 0")
    E("  kb[4]=m%256 m=" .. vSV .. ".mf(m/256) kb[5]=m%256 m=" ..
        vSV .. ".mf(m/256)")
    E("  kb[6]=m%256 m=" .. vSV .. ".mf(m/256) kb[7]=m%256")
    E("  local j=0 for i=0,255 do j=(j+S[i]+kb[i%8])%256 S[i],S[j]=S[j],S[i] end")
    E("  return S")
    E("end")

    E("local function " .. vR4D .. "(arr,ki,mx)")
    E("  local S=" .. vKSA .. "(ki,mx) local ii,j=0,0 local r={}")
    E("  for n=1,#arr do")
    E("    ii=(ii+1)%256 j=(j+S[ii])%256")
    E("    S[ii],S[j]=S[j],S[ii]")
    E("    r[n]=" .. vXOR .. "(arr[n],S[(S[ii]+S[j])%256])")
    E("  end return r")
    E("end")

    E("local function _r4d_str(arr,ki,mx)")
    E("  local S=" .. vKSA .. "(ki,mx) local ii,j=0,0 local r={}")
    E("  for n=1,#arr do")
    E("    ii=(ii+1)%256 j=(j+S[ii])%256")
    E("    S[ii],S[j]=S[j],S[ii]")
    E("    r[n]=" .. vSV .. ".sc(" .. vXOR .. "(arr[n],S[(S[ii]+S[j])%256]))")
    E("  end return " .. vSV .. ".tc(r)")
    E("end")

    E("local function " .. vFED .. "(arr,key,rounds)")
    E("  rounds=rounds or 3")
    E("  local n=#arr if n<1 then return arr end")
    E("  local res={} for i=1,n do res[i]=arr[i] end")
    E("  for r=rounds,1,-1 do")
    E("    local prev=" .. vXOR .. "(key%256,r*97%256) local tmp={}")
    E("    for i=1,n do")
    E("      local carry=(prev*131+r*83+i*17)%256")
    E("      local orig=" .. vXOR .. "(res[i],carry)")
    E("      prev=orig tmp[i]=orig")
    E("    end res=tmp")
    E("  end return res")
    E("end")

    E("local function " .. vFMX .. "(idx,seed) return (idx*7919+seed*31)%65536 end")

    local vRKH = V[160]
    E("local function " .. vRKH .. "(k)")
    E("  local h,tmp=0,k")
    E("  for _=1,4 do")
    E("    h=(h*167+tmp%256)%65536")
    E("    tmp=math.floor(tmp/256)")
    E("  end return h")
    E("end")

    -- ================================================================
    -- [NEW] 解释器完整性检测
    -- 验证标准C函数行为和版本一致性，检测解释器级patch/hook
    -- ================================================================
    E("local function " .. vINTRP .. "()")
    E("  local _sv=" .. vSV)
    -- Check 1: _VERSION 存在且长度合理
    E("  local _ver=_VERSION or ''")
    E("  if #_ver<3 then _sv.er(" .. _SE("NB:interp-no-ver") .. ") end")
    -- Check 2: native函数的tostring包含合法标识
    E("  local _ts_pc=tostring(" .. vPCPC .. ")")
    E("  local _ts_rg=tostring(rawget)")
    E("  local _ts_mf=tostring(math.floor)")
    E("  local function _has_nat_sig(s)")
    E("    return s:find(':')~=nil or s:find('function')~=nil or s:find('builtin')~=nil")
    E("  end")
    E("  if not _has_nat_sig(_ts_pc) then _sv.er(" .. _SE("NB:interp-sig-pc") .. ") end")
    E("  if not _has_nat_sig(_ts_rg) then _sv.er(" .. _SE("NB:interp-sig-rg") .. ") end")
    -- Check 3: 行为一致性检测
    E("  if math.floor(0.9)~=0 then _sv.er(" .. _SE("NB:interp-floor-1") .. ") end")
    E("  if math.floor(-0.1)~=-1 then _sv.er(" .. _SE("NB:interp-floor-2") .. ") end")
    E("  if math.floor(1.0)~=1 then _sv.er(" .. _SE("NB:interp-floor-3") .. ") end")
    E("  if type(nil)~=" .. _SE("nil") .. " then _sv.er(" .. _SE("NB:interp-type-nil") .. ") end")
    E("  if type(true)~=" .. _SE("boolean") .. " then _sv.er(" .. _SE("NB:interp-type-bool") .. ") end")
    E("  if type(0)~=" .. _SE("number") .. " then _sv.er(" .. _SE("NB:interp-type-num") .. ") end")
    -- Check 4: string.byte/char 关键点往返验证
    E("  local _b1=string.byte(string.char(0)) if _b1~=0 then _sv.er(" .. _SE("NB:interp-str-0") .. ") end")
    E("  local _b2=string.byte(string.char(255)) if _b2~=255 then _sv.er(" .. _SE("NB:interp-str-255") .. ") end")
    E("  local _b3=string.byte(string.char(127)) if _b3~=127 then _sv.er(" .. _SE("NB:interp-str-127") .. ") end")
    -- Check 5: pcall error传播行为
    E("  local _ok1,_e1=" .. vPCPC .. "(error," .. _SE("__nb_interp_test__") .. ",0)")
    E("  if _ok1 then _sv.er(" .. _SE("NB:interp-pcall-ok") .. ") end")
    E("  if _e1~=" .. _SE("__nb_interp_test__") .. " then _sv.er(" .. _SE("NB:interp-pcall-err") .. ") end")
    -- Check 6: table长度操作符行为
    E("  local _tt={1,2,3,4,5}")
    E("  if #_tt~=5 then _sv.er(" .. _SE("NB:interp-tbl-len") .. ") end")
    E("  table.remove(_tt)")
    E("  if #_tt~=4 then _sv.er(" .. _SE("NB:interp-tbl-rm") .. ") end")
    -- Check 7: debug.getinfo 显示C函数为 'C' (如可用)
    E("  if " .. vCAP .. ".has_dgi and " .. vPCDB .. " then")
    E("    local _ok2,_inf=" .. vPCPC .. "(" .. vPCDB .. ".getinfo,math.floor," .. _SE("S") .. ")")
    E("    if _ok2 and _inf and _inf.what and _inf.what~=" .. _SE("C") ..
        " then _sv.er(" .. _SE("NB:interp-natv-mf") .. ") end")
    E("    local _ok3,_inf2=" .. vPCPC .. "(" .. vPCDB .. ".getinfo," .. vPCPC .. "," .. _SE("S") .. ")")
    E("    if _ok3 and _inf2 and _inf2.what and _inf2.what~=" .. _SE("C") ..
        " then _sv.er(" .. _SE("NB:interp-natv-pc") .. ") end")
    E("  end")
    -- Check 8: 元表行为一致性
    E("  local _mt_t=setmetatable({},{__index=function(_,_k) return _k==" ..
        _SE("__nb_k") .. " and 9931 or nil end})")
    E("  if _mt_t[" .. _SE("__nb_k") .. "]~=9931 then _sv.er(" ..
        _SE("NB:interp-mt-idx") .. ") end")
    -- Check 9: 协程基础行为（若可用）
    E("  if type(coroutine)=='table' and type(coroutine.create)=='function' then")
    E("    local _nco=coroutine.create(function() end)")
    E("    if coroutine.status(_nco)~=" .. _SE("suspended") ..
        " then _sv.er(" .. _SE("NB:interp-coro-stat") .. ") end")
    E("    coroutine.resume(_nco)")
    E("    if coroutine.status(_nco)~=" .. _SE("dead") ..
        " then _sv.er(" .. _SE("NB:interp-coro-dead") .. ") end")
    E("  end")
    -- Check 10: string.format 数值一致性（检测解释器数值系统）
    E("  local _sf_ok," .. "_sf_r=" .. vPCPC ..
        "(string.format," .. _SE("%d") .. ",100)")
    E("  if _sf_ok and _sf_r~=" .. _SE("100") ..
        " then _sv.er(" .. _SE("NB:interp-sfmt") .. ") end")
    E("end")

    -- ================================================================
    -- 源码碎片数据
    -- ================================================================
    E("local " .. vFR .. "={")
    for i, frag in ipairs(enc_frags) do E("  [" .. i .. "]=" .. _A2L(frag) .. ",") end
    E("}")

    -- ================================================================
    -- [NEW] 8-slot 统一VM池字节码
    -- ================================================================
    for si = 1, TOTAL_SLOTS do
        E("local " .. vVMPOOL[si] .. "=" .. _A2L(vm_enc_bytes[si]))
    end

    -- VM常量池
    local kparts = {}
    for i, v in ipairs(payload_consts) do kparts[i] = tostring(v) end
    E("local " .. vVMCK_v .. "={" .. _tc(kparts,",") .. "}")

    -- [NEW] 8个运行时密钥数组
    local vm_runtime_keys_str = {}
    for si = 1, TOTAL_SLOTS do
        vm_runtime_keys_str[si] = tostring(VM_KEYS[si])
    end
    E("local " .. vVMKEYS .. "={" .. _tc(vm_runtime_keys_str,",") .. "}")
    E("local " .. vRVMEH .. "=" .. RVM_EHASH)
    E("local " .. vPEXEC .. "=false")

    -- 5个伪VM数据
    for fi = 1, CONFIG.FAKE_VM_COUNT do
        E("local " .. vFDATA[fi] .. "=" .. _A2L(fake_enc_data[fi]))
    end

    -- ================================================================
    -- [NEW] 间接防护跳转表（深度隐藏技术调用）
    -- 所有防护函数通过数字索引调用，分析者看不到直接调用关系
    -- ================================================================
    -- 在生成代码后期填充vDISP，这里先声明
    E("local " .. vDISP .. "={}")

    -- ================================================================
    -- 内存熵检测
    -- ================================================================
    if CONFIG.ENABLE_ENTROPY_TREND then
        E("local " .. vENTB .. "={}")
        E("local " .. vENTB .. "_head=1")
        E("local function _ent_push(v)")
        E("  " .. vENTB .. "[" .. vENTB .. "_head]=v")
        E("  " .. vENTB .. "_head=" .. vENTB .. "_head%" .. ENT_WIN .. "+1")
        E("end")
        E("local function _ent_check()")
        E("  if not " .. vCAP .. ".has_db then return end")
        E("  local cnt=0 for _ in pairs(" .. vPCDB .. ") do cnt=cnt+1 end")
        E("  _ent_push(cnt)")
        E("  if #" .. vENTB .. "<" .. ENT_WIN .. " then")
        E("    " .. vIH .. "=(" .. vIH .. "==0) and cnt or " .. vIH)
        E("    return")
        E("  end")
        E("  local _mn,_mx=" .. vENTB .. "[1]," .. vENTB .. "[1]")
        E("  for _,_v in ipairs(" .. vENTB .. ") do")
        E("    if _v<_mn then _mn=_v end")
        E("    if _v>_mx then _mx=_v end")
        E("  end")
        E("  if _mx-_mn>2 then " .. vSV .. ".er(" .. _SE("NB:entropy-spike") .. ") end")
        E("end")
    end

    -- ================================================================
    -- 行为指纹
    -- ================================================================
    if CONFIG.ENABLE_BEHAVIORAL_FINGERPRINT then
        E("local " .. vBFPR .. "=(function()")
        E("  local fp={}")
        E("  local _ok1,_e1=" .. vPCPC ..
            "(function() error(" .. _SE("_nebulae_fp_") .. ",2) end)")
        E("  fp.pcall_err_type=type(_e1)")
        E("  fp.pcall_err_is_str=type(_e1)=='string'")
        E("  local _ok2,_e2=" .. vPCPC ..
            "(function() error(nil,0) end)")
        E("  fp.pcall_nil_ok=not _ok2")
        E("  local _t3={}")
        E("  fp.rawget_nil=(" .. vPCRG .. "(_t3," .. _SE("__nk_test") .. ")==nil)")
        E("  fp.floor_3h=math.floor(3.7)==3")
        E("  fp.floor_neg=math.floor(-1.1)==-2")
        E("  return fp")
        E("end)()")

        E("local function _bfp_verify()")
        E("  local _ok1,_e1=" .. vPCPC ..
            "(function() error(" .. _SE("_nebulae_fp_") .. ",2) end)")
        E("  if type(_e1)~=" .. vBFPR ..
            ".pcall_err_type then " .. vSV ..
            ".er(" .. _SE("NB:bfp-pcall-err-type") .. ") end")
        E("  if (type(_e1)=='string')~=" .. vBFPR ..
            ".pcall_err_is_str then " .. vSV ..
            ".er(" .. _SE("NB:bfp-pcall-str") .. ") end")
        E("  if math.floor(3.7)~=3 or math.floor(-1.1)~=-2 then " ..
            vSV .. ".er(" .. _SE("NB:bfp-floor") .. ") end")
        E("  if " .. vPCRG .. "({},'" .. "__nk_test" ..
            "') ~= nil then " .. vSV ..
            ".er(" .. _SE("NB:bfp-rawget") .. ") end")
        E("end")
    end

    E("local " .. vUPVK .. "=0")
    E("local function " .. vUPBC .. "()")
    E("  if not " .. vCAP .. ".has_dgu or not " .. vPCDB .. " then return end")
    E("  if " .. vPCSD .. " then")
    E("    local _ok=" .. vPCPC .. "(" .. vPCSD .. "," ..
        vPCDB .. ".getupvalue)")
    E("    if _ok then " .. vSV ..
        ".er(" .. _SE("NB:getupvalue-lua-wrapped") .. ") end")
    E("  end")
    E("  local _t0_ok,_t0_n,_t0_v=" .. vPCPC .. "(" ..
        vPCDB .. ".getupvalue," .. vBEH0 .. ",1)")
    E("  if _t0_ok and _t0_n~=nil and _t0_n~=" ..
        _SE("_ENV") .. " then " .. vSV ..
        ".er(" .. _SE("NB:upv-behavioral-0") .. ") end")
    E("  local _t1_ok,_t1_n,_t1_v=" .. vPCPC .. "(" ..
        vPCDB .. ".getupvalue," .. vBEHC .. ",1)")
    E("  if _t1_ok and _t1_n~=nil and _t1_v~=" .. BEH_SENT ..
        " then " .. vSV ..
        ".er(" .. _SE("NB:upv-behavioral-1") .. ") end")
    E("  local _t2_ok,_t2_n=" .. vPCPC .. "(" ..
        vPCDB .. ".getupvalue," .. vBEHC .. ",2)")
    E("  if _t2_ok and _t2_n~=nil then " .. vSV ..
        ".er(" .. _SE("NB:upv-behavioral-2") .. ") end")
    E("end")

    E("local function " .. vRLD .. "()")
    E("  if " .. vPCSD .. " then")
    E("    if " .. vPCPC .. "(" .. vPCSD .. "," .. vPCLD ..
        ") then " .. vSV ..
        ".er(" .. _SE("IMMUNE:load-hooked-late") .. ") end")
    E("    if " .. vPCPC .. "(" .. vPCSD .. "," .. vPCPC ..
        ") then " .. vSV ..
        ".er(" .. _SE("IMMUNE:pcall-hooked-late") .. ") end")
    E("    if " .. vPCPC .. "(" .. vPCSD .. ",rawget) then " ..
        vSV .. ".er(" .. _SE("IMMUNE:rawget-replaced") .. ") end")
    E("    local vf=function() return " .. vRTC .. " end")
    E("    local dok,dr=" .. vPCPC .. "(" .. vPCSD .. ",vf)")
    E("    if not dok or type(dr)~='string' or #dr<4 then " ..
        vSV .. ".er(" .. _SE("IMMUNE:dump-hijacked") .. ") end")
    E("  elseif " .. vCAP .. ".has_dgi then")
    E("    local nw=" .. vCAP .. ".native_what")
    E("    local function chk(f)")
    E("      local ok,inf=" .. vPCPC .. "(" ..
        vPCDB .. ".getinfo,f," .. _SE("S") .. ")")
    E("      if ok and inf and inf.what~=nw then " ..
        vSV .. ".er(" .. _SE("IMMUNE:fn-hooked") .. ") end")
    E("    end")
    E("    chk(_LST) chk(rawget) chk(" .. vPCPC .. ")")
    E("  end")
    E("end")

    E("local function " .. vCH .. "()")
    E("  if " .. vCAP .. ".has_dsh and " ..
        vSDB .. ".sethook then " .. vPCPC .. "(" .. vSDB .. ".sethook) end")
    E("end")

    E("local function " .. vADH .. "()")
    E("  if " .. vCAP .. ".has_dgh and " .. vSDB .. ".gethook then")
    E("    local hf=" .. vSDB .. ".gethook()")
    E("    if hf~=nil then " .. vCH .. "() " ..
        vSV .. ".er(" .. _SE("HD:gethook") .. ") end")
    E("  end")
    E("  if " .. vCAP .. ".has_db then")
    E("    local cnt=0 for _ in pairs(" ..
        vPCDB .. ") do cnt=cnt+1 end")
    E("    if cnt~=" .. vCAP ..
        ".db_count then " .. vSV ..
        ".er(" .. _SE("HD:dbcount") .. ") end")
    E("  end")
    E("  if " .. vCAP .. ".is_luau and " ..
        vPCDB .. " and type(" .. vPCDB .. ".info)=='function' then")
    E("    local ok,info=" .. vPCPC .. "(" ..
        vPCDB .. ".info,1," .. _SE("s") .. ")")
    E("    if ok and type(info)=='string' and #info>100 then " ..
        vSV .. ".er(" .. _SE("HD:luau-trace") .. ") end")
    E("  end")
    E("end")

    E("local " .. vSTK .. "=0")
    E("local function " .. vSEL .. "()")
    E("  if " .. vCAP .. ".has_dgi then")
    E("    local ok,inf=" .. vPCPC .. "(" ..
        vPCDB .. ".getinfo,4," .. _SE("S") .. ")")
    E("    if ok and inf and inf.what~=" ..
        _SE("C") .. " and inf.what~=" .. _SE("main") .. " then")
    E("      local ok2,inf2=" .. vPCPC .. "(" ..
        vPCDB .. ".getinfo,8," .. _SE("S") .. ")")
    E("      if ok2 and inf2 then " ..
        vSV .. ".er(" .. _SE("HD:stackdepth") .. ") end")
    E("    end")
    E("  end")
    E("  " .. vSTK .. "=" .. vSTK .. "+1")
    E("end")

    local secret = _mr(100000, 999999)
    E("local " .. vPOI .. "=(function()")
    E("  local _s=" .. secret)
    E("  local _c=0")
    E("  return function()")
    E("    _c=_c+1")
    E("    if _s~=" .. secret ..
        " then " .. vSV .. ".er(" .. _SE("HD:upv-poison") .. ") end")
    E("    if _c<1 or _c>1000000 then " ..
        vSV .. ".er(" .. _SE("HD:upv-c") .. ") end")
    E("  end")
    E("end)()")

    if CONFIG.ENABLE_CORO_TIMING then
        E("local function " .. vCRT .. "()")
        E("  if not (type(coroutine)=='table' and type(coroutine.create)=='function') then return end")
        E("  local _done=false")
        E("  local _co=coroutine.create(function() _done=true end)")
        E("  local _t0=" .. vCLK .. "()")
        E("  coroutine.resume(_co)")
        E("  local _el=" .. vCLK .. "()-_t0")
        E("  if not _done then " ..
            vSV .. ".er(" .. _SE("NB:coro-dead") .. ") end")
        E("  if _el>0.01 then " ..
            vSV .. ".er(" .. _SE("NB:coro-timing") .. ") end")
        E("  if coroutine.status(_co)~=" ..
            _SE("dead") .. " then " ..
            vSV .. ".er(" .. _SE("NB:coro-status") .. ") end")
        E("end")
    end

    if CONFIG.ENABLE_EXEC_DETECT then
        local exec_fns = {"getrawmetatable","setrawmetatable","hookfunction",
            "hookmetamethod","newcclosure","islclosure","iscclosure","checkcaller",
            "getupvalues","getconnections","firesignal","getsenv","getscripts",
            "getgenv","decompile","getscriptbytecode","readfile","writefile",
            "loadfile","request","identifyexecutor","getproto"}
        local esigs = {}
        for _, s in ipairs(exec_fns) do esigs[#esigs+1] = _SE(s) end
        E("local function " .. vEXD .. "()")
        E("  if not " .. vCAP .. ".is_luau then return end")
        E("  local _hit=0")
        for _, enc in ipairs(esigs) do
            E("  if type(" .. vPCRG .. "(_GR," .. enc ..
                "))=='function' then _hit=_hit+1 end")
        end
        E("  if _hit>=3 then")
        if CONFIG.EXEC_DETECT_MODE == "corrupt" then
            E("    " .. vSKEY .. "=(" .. vSKEY ..
                "+_hit*13579)%65536+100")
            E("    " .. vBK .. "=(" .. vBK ..
                "+_hit*7919)%65536+100")
            E("    " .. vENVOFF .. "=(" .. vENVOFF ..
                "+_hit*3)%" .. TOTAL_SLOTS)
        else
            E("    " .. vSV .. ".er(" .. _SE("NB:exec-detected") .. ")")
        end
        E("  end")
        E("  local _bes=" .. _mr(10000,99999))
        E("  local function _bef() return _bes end")
        E("  if " .. vCAP .. ".has_dgu and " .. vPCDB .. " then")
        E("    local _ok,_n,_v=" .. vPCPC ..
            "(" .. vPCDB .. ".getupvalue,_bef,1)")
        E("    if _ok and _n~=nil and _v~=_bes then " ..
            vSV .. ".er(" .. _SE("NB:exec-upv-behavioral") .. ") end")
        E("  end")
        E("end")
    end

    if CONFIG.ENABLE_MULTI_CLOCK then
        E("local function " .. vMCK .. "()")
        E("  local oc=" .. vCLK)
        E("  local t0=oc() local s=0")
        E("  for i=1,1000 do s=s+i end")
        E("  local el=oc()-t0")
        E("  if el>" .. vTHR ..
            " then " .. vSV .. ".er(" .. _SE("HD:timing-oc") .. ") end")
        E("  local ptk=" .. vPCTK)
        E("  if ptk then")
        E("    local tk0=ptk() local cl0=oc()")
        E("    local ss=0 for i=1,500 do ss=ss+i end")
        E("    local tke=ptk()-tk0 local cle=oc()-cl0")
        E("    if tke>0.000001 and cle>0.000001 then")
        E("      local ratio=cle/tke")
        E("      if ratio<0.05 or ratio>20 then " ..
            vSV .. ".er(" .. _SE("HD:clock-ratio") .. ") end")
        E("    end")
        E("  end")
        E("  local now=oc()")
        E("  if " .. vTM .. ">0 and now<" .. vTM ..
            " then " .. vSV .. ".er(" .. _SE("HD:clock-bwd") .. ") end")
        E("  " .. vTM .. "=now")
        E("end")
    end

    if CONFIG.ENABLE_SV_INTEGRITY then
        E("local function " .. vSVI .. "()")
        E("  if " .. vSV .. ".oc~=" .. vCLK ..
            " then " .. vSV .. ".er(" .. _SE("HD:sv-oc") .. ") end")
        E("  if " .. vSV .. ".tc~=table.concat then " ..
            vSV .. ".er(" .. _SE("HD:sv-tc") .. ") end")
        E("  if " .. vSV .. ".sc~=string.char then " ..
            vSV .. ".er(" .. _SE("HD:sv-sc") .. ") end")
        E("  if " .. vSV .. ".mf~=math.floor then " ..
            vSV .. ".er(" .. _SE("HD:sv-mf") .. ") end")
        E("  if " .. vSV .. ".pc~=" .. vPCPC ..
            " then " .. vSV .. ".er(" .. _SE("HD:sv-pc") .. ") end")
        E("  if " .. vSV .. ".ld~=" .. vPCLD ..
            " then " .. vSV .. ".er(" .. _SE("HD:sv-ld") .. ") end")
        E("end")
    end

    if CONFIG.ENABLE_FUNC_HASH then
        E("local function " .. vFHC .. "()")
        E("  if not " .. vPCSD .. " then return end")
        E("  local ok,d=" .. vPCPC .. "(" .. vPCSD .. "," .. vR4D .. ")")
        E("  if not ok or type(d)~='string' or #d<4 then return end")
        E("  local h=0 for i=1,#d do h=(h*31+" ..
            vSV .. ".sb(d,i))%16777216 end")
        E("  if " .. vFH .. "==0 then " .. vFH .. "=h return end")
        E("  if h~=" .. vFH ..
            " then " .. vSV .. ".er(" .. _SE("HD:func-hash") .. ") end")
        E("end")
    end

    if CONFIG.ENABLE_NATIVE_GUARD then
        E("local function " .. vNG .. "()")
        E("  if " .. vPCSD .. " then")
        E("    if " .. vPCPC .. "(" .. vPCSD .. "," ..
            vSV .. ".ld) then " ..
            vSV .. ".er(" .. _SE("IMMUNE:ld-not-native") .. ") end")
        E("    if " .. vPCPC .. "(" .. vPCSD .. "," ..
            vSV .. ".tc) then " ..
            vSV .. ".er(" .. _SE("IMMUNE:tc-not-native") .. ") end")
        E("    if " .. vPCPC .. "(" .. vPCSD .. "," ..
            vSV .. ".sc) then " ..
            vSV .. ".er(" .. _SE("IMMUNE:sc-not-native") .. ") end")
        E("  elseif " .. vCAP .. ".has_dgi then")
        E("    local nw=" .. vCAP .. ".native_what")
        E("    local function cw(f,nm)")
        E("      local ok,inf=" .. vPCPC .. "(" ..
            vPCDB .. ".getinfo,f," .. _SE("S") .. ")")
        E("      if ok and inf and inf.what~=nw then " ..
            vSV .. ".er(" .. _SE("SV:native:") ..
            "..(nm or '?')) end")
        E("    end")
        E("    cw(" .. vSV .. ".ld," .. _SE("ld") .. ")")
        E("    cw(" .. vSV .. ".tc," .. _SE("tc") .. ")")
        E("    cw(" .. vSV .. ".sc," .. _SE("sc") .. ")")
        E("    cw(" .. vPCPC .. "," .. _SE("pc") .. ")")
        E("  end")
        if CONFIG.ENABLE_GLOBAL_REPLACE_GUARD then
            E("  if not " .. vCAP .. ".is_roblox then")
            E("    local ldf=" .. vPCRG .. "(_GR," .. _SE("load") ..
                ") or " .. vPCRG .. "(_GR," .. _SE("loadstring") .. ")")
            E("    if ldf and ldf~=" .. vPCLD ..
                " then " .. vSV .. ".er(" .. _SE("SV:ld") .. ") end")
            E("    if " .. vPCRG .. "(table," .. _SE("concat") ..
                ")~=" .. vSV .. ".tc then " ..
                vSV .. ".er(" .. _SE("SV:tc") .. ") end")
            E("  end")
        end
        E("end")
    end

    if CONFIG.ENABLE_INTEGRITY_HASH then
        local dbf = {"getinfo","sethook","gethook","getlocal",
                     "setlocal","getupvalue","setupvalue"}
        local dbe = {}
        for _, f in ipairs(dbf) do dbe[#dbe+1] = _SE(f) end
        E("local function " .. vIC .. "()")
        E("  if not " .. vCAP .. ".has_db then return true end")
        E("  local h=0")
        E("  for _,k in ipairs({" .. _tc(dbe,",") ..
            "}) do if " .. vSDB .. "[k] then h=h+1 end end")
        E("  if " .. vIH .. "==0 then " .. vIH .. "=h return true end")
        E("  return h==" .. vIH)
        E("end")
        E("local function " .. vSC2 .. "()")
        E("  if not " .. vIC .. "() then " ..
            vSV .. ".er(" .. _SE("SV:ih") .. ") end")
        E("end")
    end

    if CONFIG.ENABLE_GLOBAL_REPLACE_GUARD then
        E("local function " .. vSG .. "()")
        E("  local rs=" .. vPCRG .. "(_GR," .. _SE("string") .. ")")
        E("  if rs and " .. vPCRG .. "(rs," .. _SE("char") ..
            ")~=" .. vSV .. ".sc then " ..
            vSV .. ".er(" .. _SE("SV:sc") .. ") end")
        E("  local rm=" .. vPCRG .. "(_GR," .. _SE("math") .. ")")
        E("  if rm and " .. vPCRG .. "(rm," .. _SE("floor") ..
            ")~=" .. vSV .. ".mf then " ..
            vSV .. ".er(" .. _SE("SV:mf") .. ") end")
        E("end")
    end

    -- ================================================================
    -- [NEW] 间接防护跳转表初始化
    -- 分析者看到的是数字索引调用，而非函数名
    -- ================================================================
    local DISP_KEYS = {}
    local disp_fns = {
        {vRLD,  "rld"},
        {vCH,   "ch"},
        {vADH,  "adh"},
        {vSEL,  "sel"},
        {vPOI,  "poi"},
    }
    if CONFIG.ENABLE_INTEGRITY_HASH        then disp_fns[#disp_fns+1] = {vSC2, "sc2"} end
    if CONFIG.ENABLE_GLOBAL_REPLACE_GUARD  then disp_fns[#disp_fns+1] = {vSG,  "sg" } end
    if CONFIG.ENABLE_NATIVE_GUARD          then disp_fns[#disp_fns+1] = {vNG,  "ng" } end
    if CONFIG.ENABLE_MULTI_CLOCK           then disp_fns[#disp_fns+1] = {vMCK, "mck"} end
    if CONFIG.ENABLE_SV_INTEGRITY          then disp_fns[#disp_fns+1] = {vSVI, "svi"} end
    if CONFIG.ENABLE_FUNC_HASH             then disp_fns[#disp_fns+1] = {vFHC, "fhc"} end
    if CONFIG.ENABLE_EXEC_DETECT           then disp_fns[#disp_fns+1] = {vEXD, "exd"} end
    if CONFIG.ENABLE_CORO_TIMING           then disp_fns[#disp_fns+1] = {vCRT, "crt"} end
    if CONFIG.ENABLE_BEHAVIORAL_FINGERPRINT then disp_fns[#disp_fns+1] = {"_bfp_verify", "bfp"} end
    disp_fns[#disp_fns+1] = {vUPBC, "upbc"}
    if CONFIG.ENABLE_ENTROPY_TREND then disp_fns[#disp_fns+1] = {"_ent_check", "ent"} end
    if CONFIG.ENABLE_INTERP_CHECK  then disp_fns[#disp_fns+1] = {vINTRP, "interp"} end

    -- 生成打乱的跳转表填充代码
    local disp_indices = {}
    for i, entry in ipairs(disp_fns) do
        local idx = _mr(10000, 99999)
        while disp_indices[idx] do idx = _mr(10000, 99999) end
        disp_indices[idx] = true
        DISP_KEYS[i] = idx
        E(vDISP .. "[" .. idx .. "]=" .. entry[1])
    end

    -- ================================================================
    -- 综合防护主函数（通过间接跳转表调用）
    -- ================================================================
    E("local function " .. vAH .. "()")
    E("  " .. vHCC .. "=" .. vHCC .. "+1")
    for i, entry in ipairs(disp_fns) do
        E("  " .. vDISP .. "[" .. DISP_KEYS[i] .. "]()")
    end
    E("end")

    -- ================================================================
    -- opcode重排映射表
    -- ================================================================
    E("local " .. vRMTB .. "={}")
    E("local " .. vRMCD .. "=" .. INIT_REMAP)
    local all_ops_strs = {}
    for _, op in ipairs({
        OP.LOAD_CONST, OP.LOAD_REG, OP.STORE_MEM, OP.LOAD_MEM,
        OP.ADD_RR, OP.SUB_RR, OP.MUL_RR, OP.DIV_RR, OP.MOD_RR,
        OP.XOR_RR, OP.AND_RR, OP.NOT_R, OP.NEG_R, OP.INC_R, OP.DEC_R,
        OP.CMP_EQ, OP.CMP_NE, OP.CMP_LT, OP.CMP_LE,
        OP.JMP, OP.JZ, OP.JNZ, OP.CALL_NATIVE,
        OP.PUSH, OP.POP, OP.NOP, OP.HLT,
        OP.ADD_RC, OP.XOR_RC, OP.MOD_RC, OP.FUSE_ADC_STM
    }) do
        all_ops_strs[#all_ops_strs+1] = tostring(op)
    end
    E("local _all_ops={" .. _tc(all_ops_strs,",") .. "}")

    E("local function _remap_build(key)")
    E("  local _pool={}")
    E("  for i=1,#_all_ops do _pool[i]=_all_ops[i]+0 end")
    E("  local _lcg=key%65536+1")
    E("  for i=#_pool,2,-1 do")
    E("    _lcg=(_lcg*1664525+1013904223)%4294967296")
    E("    local j=_lcg%i+1")
    E("    _pool[i],_pool[j]=_pool[j],_pool[i]")
    E("  end")
    E("  local _t={}")
    E("  for i=1,#_all_ops do _t[_pool[i]]=_all_ops[i] end")
    E("  return _t")
    E("end")
    E(vRMTB .. "=_remap_build(" ..
        vXOR .. "(" .. vBK .. "%65536," .. vSKEY .. "%65536))")

    E("local " .. vSLWD .. "={}")
    E("local " .. vSLK  .. "=0")
    E(vSLK .. "=" .. vXOR .. "(" .. vBK .. "%65536," ..
        vXOR .. "(" .. vPS .. "%65536," .. vSKEY .. "%65536))")

    E("local function _slide_decrypt(bc,start_instr,ctx_in)")
    E("  local W=" .. SW)
    E("  local IW=" .. INSTR_WIDTH)
    E("  local res={} local ctx=ctx_in")
    E("  for ii=0,W-1 do")
    E("    local base=(start_instr+ii-1)*IW+1")
    E("    if base+IW-1<=#bc then")
    E("      local chunk={}")
    E("      for j=0,IW-1 do chunk[j+1]=bc[base+j] end")
    E("      local fkey=" .. vXOR .. "(" .. vBK .. "%65536,ctx%65536)")
    E("      local mx=" .. vFMX .. "(start_instr+ii," .. vPS .. ")")
    E("      local after_fst=" .. vFED .. "(chunk,ctx%256," .. _mr(2,3) .. ")")
    E("      local dec=" .. vR4D .. "(after_fst,fkey,mx)")
    E("      for j=1,IW do res[(ii)*IW+j]=dec[j] end")
    E("      ctx=(ctx*31+(chunk[IW] or 0))%65536")
    E("    end")
    E("  end")
    E("  return res,ctx")
    E("end")

    E("local function _slide_wipe(bc,start_instr)")
    E("  local IW=" .. INSTR_WIDTH)
    E("  local base=(start_instr-1)*IW+1")
    E("  if base+IW-1<=#bc then")
    E("    for j=base,base+IW-1 do bc[j]=(bc[j]*37+0xAB)%256 end")
    E("  end")
    E("end")

    -- ================================================================
    -- 内层碎片解密
    -- ================================================================
    E("local function _rebuild_source()")
    E("  local _fr=" .. vFR)
    E("  local _bk=" .. vBK)
    E("  local _ps=" .. vPS)
    E("  local _ik=" .. vIK2)
    E("  local _flr=" .. FLR)
    E("  local _n=" .. FC)
    E("  local _bs=" .. BS)
    E("  local _mn=math.min")
    E("  local _cc=type(collectgarbage)=='function' and collectgarbage or function() end")
    E("  local function _xr(a,b) local r,m=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+m end a=math.floor(a/2) b=math.floor(b/2) m=m*2 end return r end")
    E("  local function _ksa2(ki,mx) local S={} for i=0,255 do S[i]=i end local kb={} local k=ki")
    E("    kb[0]=k%256 k=math.floor(k/256) kb[1]=k%256 k=math.floor(k/256) kb[2]=k%256 k=math.floor(k/256) kb[3]=k%256")
    E("    local m=mx or 0 kb[4]=m%256 m=math.floor(m/256) kb[5]=m%256 m=math.floor(m/256) kb[6]=m%256 m=math.floor(m/256) kb[7]=m%256")
    E("    local j=0 for i=0,255 do j=(j+S[i]+kb[i%8])%256 S[i],S[j]=S[j],S[i] end return S end")
    E("  local function _rc4s(arr,ki,mx) local S=_ksa2(ki,mx) local ii,j=0,0 local r={}")
    E("    for n=1,#arr do ii=(ii+1)%256 j=(j+S[ii])%256 S[ii],S[j]=S[j],S[ii] r[n]=string.char(_xr(arr[n],S[(S[ii]+S[j])%256])) end return table.concat(r) end")
    E("  local function _fed2(arr,key,rounds) rounds=rounds or 3 local n=#arr if n<1 then return arr end")
    E("    local res={} for i=1,n do res[i]=arr[i] end")
    E("    for r=rounds,1,-1 do local prev=_xr(key%256,r*97%256) local tmp={}")
    E("      for i=1,n do local carry=(prev*131+r*83+i*17)%256 local orig=_xr(res[i],carry) prev=orig tmp[i]=orig end res=tmp end return res end")
    E("  local function _fmx2(i2,s2) return (i2*7919+s2*31)%65536 end")
    E("  local ctx=_xr(_ps%65536,_ik%65536)")
    E("  ctx=_xr(ctx%65536," .. vSKEY .. "%65536)")
    E("  local parts={} local bi=1")
    E("  while bi<=_n do")
    E("    local bend=_mn(bi+_bs-1,_n) local batch={}")
    E("    for i=bi,bend do")
    E("      if _fr[i] and #_fr[i]>0 then")
    E("        local last=_fr[i][#_fr[i]]")
    E("        local fkey=_xr(_bk%65536,ctx%65536)")
    E("        local mx=_fmx2(i,_ps)")
    E("        local fd=_fed2(_fr[i],ctx%256,_flr)")
    E("        batch[#batch+1]=_rc4s(fd,fkey,mx)")
    E("        ctx=(ctx*31+last)%65536")
    E("        for j2=1,#_fr[i] do _fr[i][j2]=0 end _fr[i]=nil")
    E("      else batch[#batch+1]='' end")
    E("    end")
    E("    for i=1,#batch do parts[#parts+1]=batch[i] batch[i]=nil end")
    E("    batch=nil pcall(_cc,'collect') bi=bend+1")
    E("  end")
    E("  local full=table.concat(parts)")
    E("  for i=1,#parts do parts[i]=nil end parts=nil pcall(_cc,'collect')")
    E("  return full")
    E("end")

    -- ================================================================
    -- [修复] _maybe_check: 修复 vCHKC 赋值缺失 '=' 的 bug
    -- ================================================================
    E("local " .. vCHKC .. "=" .. (_mr(CHK_MIN, CONFIG.CHECK_INTERVAL_MAX)))
    E("local function _maybe_check()")
    E("  " .. vCHKC .. "=" .. vCHKC .. "-1")
    E("  if " .. vCHKC .. "<=0 then")
    E("    " .. vAH .. "()")
    -- [BUG FIX] 原来是 vCHKC .. "((" 缺少 '='，现在正确赋值
    E("    " .. vCHKC .. "=((" ..
        vHCC .. "*37+" .. vSTK .. "*13)%" ..
        CHK_RNG .. "+" .. CHK_MIN .. ")")
    E("  end")
    E("end")

    -- ================================================================
    -- 5个伪VM（诱饵load）
    -- ================================================================
    for fi = 1, CONFIG.FAKE_VM_COUNT do
        local fk = FAKE_KEYS[fi]
        local fp = FAKE_POLYS[fi]
        E("local function " .. vFKVM[fi] .. "()")
        E("  local _fd=" .. vFDATA[fi])
        E("  local _fk=" .. fk)
        E("  local _fp=" .. fp)
        E("  local _fflr=" .. FLR)
        E("  local function _fxr(a,b) local r,m=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+m end a=math.floor(a/2) b=math.floor(b/2) m=m*2 end return r end")
        E("  local function _fksa(ki,mx) local S={} for i=0,255 do S[i]=i end local kb={} local k=ki")
        E("    kb[0]=k%256 k=math.floor(k/256) kb[1]=k%256 k=math.floor(k/256) kb[2]=k%256 k=math.floor(k/256) kb[3]=k%256")
        E("    local m=mx or 0 kb[4]=m%256 m=math.floor(m/256) kb[5]=m%256 m=math.floor(m/256) kb[6]=m%256 m=math.floor(m/256) kb[7]=m%256")
        E("    local j=0 for i=0,255 do j=(j+S[i]+kb[i%8])%256 S[i],S[j]=S[j],S[i] end return S end")
        E("  local function _frc4s(arr,ki,mx) local S=_fksa(ki,mx) local ii,j=0,0 local r={}")
        E("    for n=1,#arr do ii=(ii+1)%256 j=(j+S[ii])%256 S[ii],S[j]=S[j],S[ii]")
        E("      r[n]=string.char(_fxr(arr[n],S[(S[ii]+S[j])%256])) end return table.concat(r) end")
        E("  local function _ffed(arr,key,rounds) rounds=rounds or 3 local n=#arr if n<1 then return arr end")
        E("    local res={} for i=1,n do res[i]=arr[i] end")
        E("    for r=rounds,1,-1 do local prev=_fxr(key%256,r*97%256) local tmp={}")
        E("      for i=1,n do local carry=(prev*131+r*83+i*17)%256 local orig=_fxr(res[i],carry) prev=orig tmp[i]=orig end res=tmp end return res end")
        E("  local _fd2=_ffed(_fd,_fk%256,_fflr)")
        E("  local _fsrc=_frc4s(_fd2,_fk,_fp)")
        E("  local _ffn,_ferr=_LST(_fsrc)")
        E("  if _ffn then pcall(_ffn) end")
        E("end")
    end

    -- ================================================================
    -- 真VM执行引擎
    -- ================================================================
    local vVMSEL = V[165]
    E("local " .. vVMSEL .. "=false")

    E("local function " .. vVMEX ..
        "(bc,consts,nat,rvm_key)")
    E("  local R={0,0,0,0,0,0,0,0}")
    E("  local S={} local sp=0 local M={}")
    E("  local IW=" .. INSTR_WIDTH)
    E("  local mf=math.floor")
    E("  local xf=" .. vXOR)
    E("  local remap=" .. vRMTB)
    E("  local remap_cd=" .. vRMCD)
    E("  local remap_min=" .. REMAP_MIN)
    E("  local remap_rng=" .. REMAP_RNG)
    E("  local stp=0")
    E("  local slctx=xf(rvm_key%65536,xf(" .. vPS ..
        "%65536," .. vSKEY .. "%65536))")
    E("  local pc=1")
    E("  local total_instrs=mf(#bc/IW)")
    E("  while pc<=total_instrs do")
    E("    local _wdec,_nctx=_slide_decrypt(bc,pc,slctx)")
    E("    slctx=_nctx")
    E("    local _i1=_wdec[1] or 0")
    E("    local _i2=_wdec[2] or 0")
    E("    local _i3=_wdec[3] or 0")
    E("    local _i4=_wdec[4] or 0")
    E("    local _i5=_wdec[5] or 0")
    E("    local real_op=remap[_i1] or _i1")
    E("    stp=stp+1")
    E("    _maybe_check()")
    E("    remap_cd=remap_cd-1")
    E("    if remap_cd<=0 then")
    E("      local _nk=((" .. vSKEY ..
        "+stp*13+(R[1] or 0)*7+(R[2] or 0)*3)%65436)+100")
    E("      remap=_remap_build(xf(" .. vBK ..
        "%65536,_nk%65536))")
    E("      " .. vRMTB .. "=remap")
    E("      remap_cd=((_nk*41+stp*17+(R[3] or 0)*11)%remap_rng+remap_min)")
    E("    end")
    E("    _slide_wipe(bc,pc)")
    E("    local np=pc+1")
    E("    if real_op==" .. OP.LOAD_CONST .. " then")
    E("      R[_i2+1]=consts[_i3+1] or 0")
    E("    elseif real_op==" .. OP.LOAD_REG .. " then")
    E("      R[_i2+1]=R[_i3+1]")
    E("    elseif real_op==" .. OP.STORE_MEM .. " then")
    E("      M[_i2]=R[_i3+1]")
    E("    elseif real_op==" .. OP.LOAD_MEM .. " then")
    E("      R[_i2+1]=M[_i3] or 0")
    E("    elseif real_op==" .. OP.ADD_RR .. " then")
    E("      R[_i2+1]=R[_i3+1]+R[_i4+1]")
    E("    elseif real_op==" .. OP.SUB_RR .. " then")
    E("      R[_i2+1]=R[_i3+1]-R[_i4+1]")
    E("    elseif real_op==" .. OP.MUL_RR .. " then")
    E("      R[_i2+1]=R[_i3+1]*R[_i4+1]")
    E("    elseif real_op==" .. OP.DIV_RR .. " then")
    E("      local _dv=R[_i4+1]")
    E("      R[_i2+1]=mf(R[_i3+1]/(_dv==0 and 1 or _dv))")
    E("    elseif real_op==" .. OP.MOD_RR .. " then")
    E("      local _mv=R[_i4+1]")
    E("      R[_i2+1]=R[_i3+1]%(_mv==0 and 1 or _mv)")
    E("    elseif real_op==" .. OP.XOR_RR .. " then")
    E("      R[_i2+1]=xf(R[_i3+1],R[_i4+1])")
    E("    elseif real_op==" .. OP.AND_RR .. " then")
    E("      local _a,_b=R[_i3+1],R[_i4+1] local _r=0 local _m=1")
    E("      while _a>0 and _b>0 do")
    E("        if _a%2==1 and _b%2==1 then _r=_r+_m end")
    E("        _a=mf(_a/2) _b=mf(_b/2) _m=_m*2")
    E("      end")
    E("      R[_i2+1]=_r")
    E("    elseif real_op==" .. OP.NOT_R .. " then")
    E("      R[_i2+1]=(R[_i3+1]==0) and 1 or 0")
    E("    elseif real_op==" .. OP.NEG_R .. " then")
    E("      R[_i2+1]=-R[_i3+1]")
    E("    elseif real_op==" .. OP.INC_R .. " then")
    E("      R[_i2+1]=R[_i2+1]+1")
    E("    elseif real_op==" .. OP.DEC_R .. " then")
    E("      R[_i2+1]=R[_i2+1]-1")
    E("    elseif real_op==" .. OP.CMP_EQ .. " then")
    E("      R[_i2+1]=(R[_i3+1]==R[_i4+1]) and 1 or 0")
    E("    elseif real_op==" .. OP.CMP_NE .. " then")
    E("      R[_i2+1]=(R[_i3+1]~=R[_i4+1]) and 1 or 0")
    E("    elseif real_op==" .. OP.CMP_LT .. " then")
    E("      R[_i2+1]=(R[_i3+1]<R[_i4+1]) and 1 or 0")
    E("    elseif real_op==" .. OP.CMP_LE .. " then")
    E("      R[_i2+1]=(R[_i3+1]<=R[_i4+1]) and 1 or 0")
    E("    elseif real_op==" .. OP.JMP .. " then")
    E("      np=_i2+1")
    E("    elseif real_op==" .. OP.JZ .. " then")
    E("      if R[_i2+1]==0 then np=_i3+1 end")
    E("    elseif real_op==" .. OP.JNZ .. " then")
    E("      if R[_i2+1]~=0 then np=_i3+1 end")
    E("    elseif real_op==" .. OP.CALL_NATIVE .. " then")
    E("      local nid=consts[_i2+1]")
    E("      local nf=nat[nid]")
    E("      if nf then nf(R,M,consts) end")
    E("    elseif real_op==" .. OP.PUSH .. " then")
    E("      sp=sp+1 S[sp]=R[_i2+1]")
    E("    elseif real_op==" .. OP.POP .. " then")
    E("      R[_i2+1]=S[sp] or 0 S[sp]=nil sp=sp-1")
    E("    elseif real_op==" .. OP.ADD_RC .. " then")
    E("      R[_i2+1]=R[_i3+1]+(consts[_i4+1] or 0)")
    E("    elseif real_op==" .. OP.XOR_RC .. " then")
    E("      R[_i2+1]=xf(R[_i3+1],consts[_i4+1] or 0)")
    E("    elseif real_op==" .. OP.MOD_RC .. " then")
    E("      local _kv=consts[_i4+1] or 1")
    E("      R[_i2+1]=R[_i3+1]%(_kv==0 and 1 or _kv)")
    E("    elseif real_op==" .. OP.FUSE_ADC_STM .. " then")
    E("      R[_i2+1]=R[_i3+1]+R[_i4+1] M[_i5]=R[_i2+1]")
    E("    elseif real_op==" .. OP.NOP .. " then")
    E("      local _nb=0 _nb=_nb+0")
    E("    elseif real_op==" .. OP.HLT .. " then")
    E("      break")
    E("    end")
    E("    pc=np")
    E("  end")
    E("end")

    -- ================================================================
    -- Native函数表（NID_EXEC通过__call元表调用load，完整VM-load路径）
    -- ================================================================
    E("local _NTV={}")
    E("_NTV[" .. NID_INIT .. "]=function(R,M,K) " .. vAH .. "() end")
    E("_NTV[" .. NID_CHK  .. "]=function(R,M,K) _maybe_check() end")
    E("_NTV[" .. NID_EXEC .. "]=function(R,M,K)")
    E("  if not " .. vVMSEL .. " then return end")
    E("  " .. vPEXEC .. "=true")
    E("  local src=_rebuild_source()")
    E("  if not src or src=='' then " ..
        vSV .. ".er(" .. _SE("VM:empty-src") .. ") end")
    E("  local bG=_GR or {}")
    local sfe_l = "_sfe_" .. RT_CHECK
    local ld_l  = "_ld_"  .. RT_CHECK
    local cap_l = "_cap_" .. RT_CHECK
    E("  local " .. sfe_l .. "=" .. vSV .. ".sfe")
    E("  local " .. ld_l  .. "=" .. vHLDTBL .. "[" .. vHLDIDX .. "]")
    E("  local " .. cap_l .. "=" .. vCAP)
    E("  local env=setmetatable({},{")
    E("    __index=function(t,k)")
    for _, kk in ipairs({"table","string","math","pcall","error","rawget","rawset",
                          "setmetatable","type","tostring","tonumber","ipairs","pairs",
                          "select","print","assert","next","warn","unpack",
                          "collectgarbage","load","loadstring"}) do
        if kk == "unpack" then
            E("      if k==" .. _SE(kk) .. " then return table.unpack or unpack end")
        elseif kk == "collectgarbage" then
            E("      if k==" .. _SE(kk) .. " then return " .. vSV .. ".cc end")
        elseif kk == "load" or kk == "loadstring" then
            E("      if k==" .. _SE(kk) .. " then return " .. ld_l .. " end")
        else
            E("      if k==" .. _SE(kk) .. " then return " .. kk .. " end")
        end
    end
    E("      return bG[k]")
    E("    end,")
    E("    __newindex=function(t,k,v) bG[k]=v end")
    E("  })")
    E("  env.table=table env.string=string env.math=math")
    E("  env.pcall=pcall env.error=error env.rawget=rawget env.rawset=rawset")
    E("  env.setmetatable=setmetatable env.type=type env.tostring=tostring")
    E("  env.tonumber=tonumber env.ipairs=ipairs env.pairs=pairs")
    E("  env.select=select env.print=print env.assert=assert env.next=next")
    E("  env.unpack=table.unpack or unpack env._ENV=env")
    E("  local fn,err")
    E("  -- [NEW] 非load路径：使用loadfile + 字节码解析")
    E("  local _exec_mode=" .. vEXEM .. " or 0")
    E("  if _exec_mode==1 then")
    E("    -- 路径1：load直接执行(source直接作为函数)")
    E("    fn,err=" .. ld_l .. "(src)")
    E("  elseif _exec_mode==2 then")
    E("    -- 路径2：dofile替代执行")
    E("    local _tmp_f=io.open(\"rb_vm_tmp\",\"wb\")")
    E("    if _tmp_f then _tmp_f:write(src) _tmp_f:close() end")
    E("    local _ok,_e=pcall(dofile,\"rb_vm_tmp\")")
    E("    if _tmp_f then _tmp_f:close() end")
    E("    local _rm=os.remove")
    E("    local _removed=(_rm and _rm(\"rb_vm_tmp\"))")
    E("    if not _ok then error(\"VM:exec-dofile:\"..tostring(_e)) end")
    E("  elseif _exec_mode==3 then")
    E("    -- 路径3：直接使用load执行每个chunk")
    E("    local _lines={}")
    E("    string.gsub(src..'\\n','([^\\n]+)\\n',function(c) _lines[#_lines+1]=c end)")
    E("    local _run_fn=load or loadstring")
    E("    for _i=1,#_lines do")
    E("      local _fn,err=_run_fn(_lines[_i])")
    E("      if _fn then pcall(_fn) elseif err then end")
    E("    end")
    E("  else")
    E("    -- 原load路径(默认fallback)")
    E("    if " .. cap_l .. ".is_luau then")
    E("      fn,err=" .. ld_l .. "(src)")
    E("    elseif " .. cap_l .. ".has_load4 then")
    E("      fn,err=" .. ld_l .. "(src," ..
        _SE("=p") .. "," .. _SE("bt") .. ",env)")
    E("    elseif " .. sfe_l .. " then")
    E("      fn,err=" .. ld_l .. "(src)")
    E("      if fn then " .. sfe_l .. "(fn,env) end")
    E("    else fn,err=" .. ld_l .. "(src) end")
    E("  end")
    E("  src=nil " .. vPCPC .. "(" .. vSV .. ".cc,'collect')")
    E("  if not fn then error(" .. vSV .. ".er(" .. _SE("NB:load-fail:") ..
        "..tostring(err))) end")
    E("  local ok,e2=" .. vPCPC .. "(fn)")
    E("  fn=nil env=nil " .. vPCPC .. "(" .. vSV .. ".cc,'collect')")
    E("  if not ok then error(" .. vSV .. ".er(" .. _SE("NB:exec-fail:") ..
        "..tostring(e2))) end")
    E("end")

    -- ================================================================
    -- CFF真状态机初始化块
    -- ================================================================
    do
        local cff_actions = {}
        local function add_action(s) cff_actions[#cff_actions+1] = s end
        add_action(vRLD .. "()")
        if CONFIG.ENABLE_NATIVE_GUARD         then add_action(vNG  .. "()") end
        add_action(vCH  .. "() " .. vADH .. "()")
        if CONFIG.ENABLE_INTEGRITY_HASH        then add_action(vIC  .. "()") end
        if CONFIG.ENABLE_GLOBAL_REPLACE_GUARD  then add_action(vSG  .. "()") end
        if CONFIG.ENABLE_SV_INTEGRITY          then add_action(vSVI .. "()") end
        if CONFIG.ENABLE_FUNC_HASH             then add_action(vFHC .. "()") end
        if CONFIG.ENABLE_EXEC_DETECT           then add_action(vEXD .. "()") end
        if CONFIG.ENABLE_CORO_TIMING           then add_action(vCRT .. "()") end
        if CONFIG.ENABLE_BEHAVIORAL_FINGERPRINT then add_action("_bfp_verify()") end
        add_action(vUPBC .. "()")
        if CONFIG.ENABLE_ENTROPY_TREND         then add_action("_ent_check()") end
        if CONFIG.ENABLE_INTERP_CHECK          then add_action(vINTRP .. "()") end

        local NA = #cff_actions
        local cff_states = {}
        local used_st = {}
        for i = 1, NA+1 do
            local s; repeat s = _mr(1000,65530) until not used_st[s]
            used_st[s] = true; cff_states[i] = s
        end
        local cff_A={}
        local cff_B={}
        local cff_M={}
        for i = 1, NA do
            cff_A[i] = _mr(2, 15)
            cff_M[i] = 32749
            cff_B[i] = (cff_states[i+1] - cff_A[i]*cff_states[i]) % cff_M[i]
        end
        local order = {}
        for i = 1, NA do order[i] = i end
        for i = NA, 2, -1 do
            local j = _mr(1,i); order[i],order[j] = order[j],order[i]
        end

        if CONFIG.ENABLE_CFF then
            local ca_str = _tc(cff_A, ",")
            local cb_str = _tc(cff_B, ",")
            local cm_str = _tc(cff_M, ",")
            E("do")
            E("  local " .. vCS .. "=" .. cff_states[1])
            E("  local " .. vCFFM .. "_a={" .. ca_str .. "}")
            E("  local " .. vCFFM .. "_b={" .. cb_str .. "}")
            E("  local " .. vCFFM .. "_m={" .. cm_str .. "}")
            E("  while " .. vCS .. "~=" .. cff_states[NA+1] .. " do")
            for _, bi in ipairs(order) do
                E("    if " .. vCS .. "==" .. cff_states[bi] .. " then")
                E("      " .. cff_actions[bi])
                E("      " .. vCS .. "=(" ..
                    vCFFM .. "_a[" .. bi .. "]*" ..
                    vCS  .. "+" ..
                    vCFFM .. "_b[" .. bi .. "])%" ..
                    vCFFM .. "_m[" .. bi .. "]")
                E("    end")
            end
            E("  end")
            E("end")
        else
            E("do")
            for _, action in ipairs(cff_actions) do E("  " .. action) end
            E("end")
        end
    end

    -- ================================================================
    -- [NEW] 启动序列：5个伪VM + 8个池化VM（真假身份由运行时熵决定）
    -- 真假VM统一进入同一执行队列，顺序由环境熵打乱
    -- ================================================================

    -- 伪VM执行（诱饵）
    local fvm_order = {}
    for fi = 1, CONFIG.FAKE_VM_COUNT do fvm_order[fi] = fi end
    for i = CONFIG.FAKE_VM_COUNT, 2, -1 do
        local j = _mr(1,i); fvm_order[i],fvm_order[j] = fvm_order[j],fvm_order[i]
    end
    E("do")
    for _, fi in ipairs(fvm_order) do
        E("  pcall(" .. vFKVM[fi] .. ")")
    end
    E("end")

    -- [NEW] 8-slot VM池：运行时用 vENVOFF 偏移决定从哪个槽开始寻找真VM
    -- 真VM槽通过密钥哈希验证（而非固定位置）
    -- 执行顺序: 从 (REAL_SLOT_IDX + vENVOFF) % TOTAL_SLOTS 开始循环
    E("do")
    -- 8个VM的字节码存入池数组
    local pool_bc_arr = {}
    for si = 1, TOTAL_SLOTS do pool_bc_arr[si] = vVMPOOL[si] end

    E("  local _pool_bc={")
    for si = 1, TOTAL_SLOTS do
        E("    [" .. si .. "]=" .. pool_bc_arr[si] .. ",")
    end
    E("  }")
    E("  local _pool_keys=" .. vVMKEYS)
    E("  local _expected_hash=" .. vRVMEH)
    -- 运行时打乱执行顺序（基于 vENVOFF）
    E("  local _exec_order={}")
    E("  for _si=1," .. TOTAL_SLOTS .. " do")
    E("    _exec_order[_si]=((" .. vENVOFF .. "+_si-1)%" .. TOTAL_SLOTS .. ")+1")
    E("  end")
    -- [NEW] 角色翻转：基于运行时熵真假角色动态交换
    E("  local _role_flip=math.random(0,1)")
    E("  if _role_flip==1 then")
    E("    local _temp=_exec_order[1]")
    E("    _exec_order[1]=_exec_order[" .. TOTAL_SLOTS .. "]")
    E("    _exec_order[" .. TOTAL_SLOTS .. "]=_temp")
    E("  end")
    -- 去重（确保每个槽只出现一次）
    E("  local _seen_slots={}")
    E("  local _dedup_order={}")
    E("  for _,_slot in ipairs(_exec_order) do")
    E("    if not _seen_slots[_slot] then")
    E("      _seen_slots[_slot]=true")
    E("      _dedup_order[#_dedup_order+1]=_slot")
    E("    end")
    E("  end")
    -- 补全未出现的槽
    E("  for _si=1," .. TOTAL_SLOTS .. " do")
    E("    if not _seen_slots[_si] then")
    E("      _dedup_order[#_dedup_order+1]=_si")
    E("    end")
    E("  end")
    -- 依次尝试每个槽
    E("  for _,_slot_idx in ipairs(_dedup_order) do")
    E("    local _rk=_pool_keys[_slot_idx]")
    -- [NEW] 真VM识别：密钥哈希验证 + 环境偏移补偿
    -- 正确环境下 vENVOFF=0，哈希直接匹配
    -- 错误环境（调试/hook）vENVOFF偏移后选中错误槽，哈希不匹配，payload不执行
    E("    local _rk_adj=(_rk+" .. vENVOFF .. "*" .. _mr(1,7) ..
        ")%65536")
    E("    if _rk_adj<100 then _rk_adj=_rk_adj+100 end")
    local vRKH_rt = V[160]
    E("    " .. vVMSEL .. "=(" .. vRKH_rt .. "(_rk)==_expected_hash)")
    E("    if _pool_bc[_slot_idx] then")
    E("      pcall(" .. vVMEX .. ",_pool_bc[_slot_idx]," ..
        vVMCK_v .. ",_NTV,_rk)")
    E("    end")
    E("    if " .. vPEXEC .. " then break end")
    E("  end")
    E("  if not " .. vPEXEC ..
        " then " .. vSV .. ".er(" ..
        _SE("NB:all-vms-failed") .. ") end")
    E("end")

    -- ================================================================
    -- 双谓词死代码
    -- ================================================================
    local vFVT   = V[50]
    local vFPOLY = V[51]
    local POLY_A = POLY_SEED
    local POLY_B = POLY_SEED + 1
    E("local " .. vFVT .. "={}")
    for i = 1, CONFIG.JUNK_INST_COUNT do
        local r = _mr(1000000, 9999999)
        E(vFVT .. "[" .. r .. "]={" ..
            _mr(1,255) .. "," ..
            _mr(0,255) .. "," ..
            _mr(1000000,9999999) .. "}")
    end
    E("local " .. vFPOLY .. "=" .. POLY_A)
    E("if (" .. vFPOLY .. "*(" .. vFPOLY .. "+1))%2~=0 or (" ..
        vFPOLY .. "-" .. POLY_B .. ")^2<0 then")
    E("  local _dc_r=type(game)=='userdata' and type(workspace)=='userdata'")
    E("  if _dc_r and type(warn)~='function' then error(" ..
        _SE("ENV:warn-missing") .. ") end")
    E("  if " .. vPCDB ..
        " and type(" .. vPCDB .. ".gethook)=='function' then")
    E("    local _dc_hf=" .. vPCDB .. ".gethook()")
    E("    if _dc_hf~=nil then error(" .. _SE("ENV:dbhook") .. ") end")
    E("  end")
    E("  local _dc_exe=0")
    E("  local _dc_sigs={" ..
        _SE("hookfunction") .. "," ..
        _SE("getrawmetatable") .. "," ..
        _SE("newcclosure") .. "," ..
        _SE("decompile") .. "}")
    E("  for _,_k in ipairs(_dc_sigs) do")
    E("    if type(" .. vPCRG ..
        "(_GR or {},_k))=='function' then _dc_exe=_dc_exe+1 end")
    E("  end")
    E("  if _dc_exe>=2 then error(" .. _SE("ENV:exec-dc") .. ") end")
    E("  local _dc_fp=" .. vFPOLY)
    E("  while " .. vFVT .. "[_dc_fp] do")
    E("    _dc_fp=" .. vFVT .. "[_dc_fp][3]")
    E("    if _dc_exe<0 then error(" .. _SE("ENV:internal") .. ") end")
    E("  end")
    E("end")

    local hdr = "--[[ Protected by Nebulae Gen15 Beta 6.2 ]]\n"
    return hdr .. _tc(body, "\n")
end

-- ============================================================
-- 入口
-- ============================================================
local function get_arg_file()
    -- 尝试多种方式获取arg参数
    local a = arg
    if type(a) == 'table' then
        -- Lua表格
        if a[1] then return a[1] end
        for k, v in pairs(a) do
            if type(k) == 'number' and k > 0 then return v end
        end
    elseif type(a) == 'string' then
        -- 字符串直接作为文件名
        if a ~= '' then return a end
    end
    
    -- [NEW] 如果arg为空，尝试从预设文件名列表中获取第一个存在的文件
    local test_files = {"demo.lua", "test.lua", "input.lua", "main.lua"}
    for _, fname in ipairs(test_files) do
        local f = io.open(fname, "r")
        if f then f:close() return fname end
    end
    
    return nil
end

local arg_file = get_arg_file()
if arg_file then
    local f = io.open(arg_file, "rb")
    if not f then print("ERR: FILE NOT FOUND: " .. tostring(arg_file)) return end
    local content = f:read("*all"); f:close()
    local ok, res = pcall(build, content)
    if not ok then print("BUILD ERR: " .. tostring(res)) return end
    local out = CONFIG.OUTPUT_PREFIX .. arg_file
    local wf = io.open(out, "wb"); wf:write(res); wf:close()
    print("[OK] " .. out .. " (" .. #res .. " bytes)")
else
    io.write("File: ")
    local input = io.read()
    if input then input = input:gsub('"',""):gsub("'","") end
    if not input or input == "" then print("ERR: NO INPUT") return end
    local f = io.open(input, "rb")
    if not f then print("ERR: FILE NOT FOUND") return end
    local content = f:read("*all"); f:close()
    local ok, res = pcall(build, content)
    if not ok then print("BUILD ERR: " .. tostring(res)) return end
    local out = CONFIG.OUTPUT_PREFIX .. input
    local wf = io.open(out, "wb"); wf:write(res); wf:close()
    print("[OK] " .. out .. " (" .. #res .. " bytes)")
end
