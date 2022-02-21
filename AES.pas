Unit AES;

{==============================================================================}
{  AES ECB, CTR and CBC encryption algorithms                                  }
{                                                                              }
{  Port of Tiny AES in C (https://github.com/kokke/tiny-AES-c)                 }
{==============================================================================}

Interface

Const AES_BLOCKLEN = 16;

{= AES-128 =}
Const AES_128_KEY_EXPONENT_SIZE = 176;

Type PAES_128_Ctx = ^TAES_128_Ctx;
     TAES_128_Ctx = Record
                      RoundKey: Array [0..AES_128_KEY_EXPONENT_SIZE - 1] of Byte;
                      Iv      : Array [0..AES_BLOCKLEN - 1] of Byte;
                   End;

Procedure AES_128_init_ctx(ctx: PAES_128_Ctx; key: Pointer);
Procedure AES_128_init_ctx_iv(ctx: PAES_128_Ctx; key, iv: Pointer);
Procedure AES_128_ctx_set_iv(ctx: PAES_128_Ctx; iv: Pointer);

Procedure AES_128_ECB_encrypt(ctx: PAES_128_Ctx; buf: Pointer);
Procedure AES_128_ECB_decrypt(ctx: PAES_128_Ctx; buf: Pointer);
Procedure AES_128_CBC_encrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);
Procedure AES_128_CBC_decrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);
Procedure AES_128_CTR_xcrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);

{= AES-192 =}
Const AES_192_KEY_EXPONENT_SIZE = 208;
Type PAES_192_Ctx = ^TAES_192_Ctx;
     TAES_192_Ctx = Record
                      RoundKey: Array [0..AES_192_KEY_EXPONENT_SIZE - 1] of Byte;
                      Iv      : Array [0..AES_BLOCKLEN - 1] of Byte;
                   End;

Procedure AES_192_init_ctx(ctx: PAES_192_Ctx; key: Pointer);
Procedure AES_192_init_ctx_iv(ctx: PAES_192_Ctx; key, iv: Pointer);
Procedure AES_192_ctx_set_iv(ctx: PAES_192_Ctx; iv: Pointer);

Procedure AES_192_ECB_encrypt(ctx: PAES_192_Ctx; buf: Pointer);
Procedure AES_192_ECB_decrypt(ctx: PAES_192_Ctx; buf: Pointer);
Procedure AES_192_CBC_encrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);
Procedure AES_192_CBC_decrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);
Procedure AES_192_CTR_xcrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);

{= AES-256 =}
Const AES_256_KEY_EXPONENT_SIZE = 240;
Type PAES_256_Ctx = ^TAES_256_Ctx;
     TAES_256_Ctx = Record
                      RoundKey: Array [0..AES_256_KEY_EXPONENT_SIZE - 1] of Byte;
                      Iv      : Array [0..AES_BLOCKLEN - 1] of Byte;
                   End;

Procedure AES_256_init_ctx(ctx: PAES_256_Ctx; key: Pointer);
Procedure AES_256_init_ctx_iv(ctx: PAES_256_Ctx; key, iv: Pointer);
Procedure AES_256_ctx_set_iv(ctx: PAES_256_Ctx; iv: Pointer);

Procedure AES_256_ECB_encrypt(ctx: PAES_256_Ctx; buf: Pointer);
Procedure AES_256_ECB_decrypt(ctx: PAES_256_Ctx; buf: Pointer);
Procedure AES_256_CBC_encrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);
Procedure AES_256_CBC_decrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);
Procedure AES_256_CTR_xcrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);

Implementation

Type
  PByteArray = ^TByteArray;
  TByteArray = Array[0..32767] of Byte;

  TState = Array[0..3, 0..3] of Byte;
  PState = ^TState;

Const COLUMNS = 4;
Const KEY_WORDS_128 = 4;
Const ROUNDS_128 = 10;
Const KEY_WORDS_192 = 6;
Const ROUNDS_192 = 12;
Const KEY_WORDS_256 = 8;
Const ROUNDS_256 = 14;

Const SBOX: Array [0..255] of Byte  = (
  //0   1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
  $63, $7c, $77, $7b, $f2, $6b, $6f, $c5, $30, $01, $67, $2b, $fe, $d7, $ab, $76,
  $ca, $82, $c9, $7d, $fa, $59, $47, $f0, $ad, $d4, $a2, $af, $9c, $a4, $72, $c0,
  $b7, $fd, $93, $26, $36, $3f, $f7, $cc, $34, $a5, $e5, $f1, $71, $d8, $31, $15,
  $04, $c7, $23, $c3, $18, $96, $05, $9a, $07, $12, $80, $e2, $eb, $27, $b2, $75,
  $09, $83, $2c, $1a, $1b, $6e, $5a, $a0, $52, $3b, $d6, $b3, $29, $e3, $2f, $84,
  $53, $d1, $00, $ed, $20, $fc, $b1, $5b, $6a, $cb, $be, $39, $4a, $4c, $58, $cf,
  $d0, $ef, $aa, $fb, $43, $4d, $33, $85, $45, $f9, $02, $7f, $50, $3c, $9f, $a8,
  $51, $a3, $40, $8f, $92, $9d, $38, $f5, $bc, $b6, $da, $21, $10, $ff, $f3, $d2,
  $cd, $0c, $13, $ec, $5f, $97, $44, $17, $c4, $a7, $7e, $3d, $64, $5d, $19, $73,
  $60, $81, $4f, $dc, $22, $2a, $90, $88, $46, $ee, $b8, $14, $de, $5e, $0b, $db,
  $e0, $32, $3a, $0a, $49, $06, $24, $5c, $c2, $d3, $ac, $62, $91, $95, $e4, $79,
  $e7, $c8, $37, $6d, $8d, $d5, $4e, $a9, $6c, $56, $f4, $ea, $65, $7a, $ae, $08,
  $ba, $78, $25, $2e, $1c, $a6, $b4, $c6, $e8, $dd, $74, $1f, $4b, $bd, $8b, $8a,
  $70, $3e, $b5, $66, $48, $03, $f6, $0e, $61, $35, $57, $b9, $86, $c1, $1d, $9e,
  $e1, $f8, $98, $11, $69, $d9, $8e, $94, $9b, $1e, $87, $e9, $ce, $55, $28, $df,
  $8c, $a1, $89, $0d, $bf, $e6, $42, $68, $41, $99, $2d, $0f, $b0, $54, $bb, $16);

Const RSBOX: Array [0..255] of Byte  = (
  //0   1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
  $52, $09, $6a, $d5, $30, $36, $a5, $38, $bf, $40, $a3, $9e, $81, $f3, $d7, $fb,
  $7c, $e3, $39, $82, $9b, $2f, $ff, $87, $34, $8e, $43, $44, $c4, $de, $e9, $cb,
  $54, $7b, $94, $32, $a6, $c2, $23, $3d, $ee, $4c, $95, $0b, $42, $fa, $c3, $4e,
  $08, $2e, $a1, $66, $28, $d9, $24, $b2, $76, $5b, $a2, $49, $6d, $8b, $d1, $25,
  $72, $f8, $f6, $64, $86, $68, $98, $16, $d4, $a4, $5c, $cc, $5d, $65, $b6, $92,
  $6c, $70, $48, $50, $fd, $ed, $b9, $da, $5e, $15, $46, $57, $a7, $8d, $9d, $84,
  $90, $d8, $ab, $00, $8c, $bc, $d3, $0a, $f7, $e4, $58, $05, $b8, $b3, $45, $06,
  $d0, $2c, $1e, $8f, $ca, $3f, $0f, $02, $c1, $af, $bd, $03, $01, $13, $8a, $6b,
  $3a, $91, $11, $41, $4f, $67, $dc, $ea, $97, $f2, $cf, $ce, $f0, $b4, $e6, $73,
  $96, $ac, $74, $22, $e7, $ad, $35, $85, $e2, $f9, $37, $e8, $1c, $75, $df, $6e,
  $47, $f1, $1a, $71, $1d, $29, $c5, $89, $6f, $b7, $62, $0e, $aa, $18, $be, $1b,
  $fc, $56, $3e, $4b, $c6, $d2, $79, $20, $9a, $db, $c0, $fe, $78, $cd, $5a, $f4,
  $1f, $dd, $a8, $33, $88, $07, $c7, $31, $b1, $12, $10, $59, $27, $80, $ec, $5f,
  $60, $51, $7f, $a9, $19, $b5, $4a, $0d, $2d, $e5, $7a, $9f, $93, $c9, $9c, $ef,
  $a0, $e0, $3b, $4d, $ae, $2a, $f5, $b0, $c8, $eb, $bb, $3c, $83, $53, $99, $61,
  $17, $2b, $04, $7e, $ba, $77, $d6, $26, $e1, $69, $14, $63, $55, $21, $0c, $7d);

Const ROUND_CONSTANT: Array[0..10] of Byte = ( $8d, $01, $02, $04, $08, $10, $20, $40, $80, $1b, $36 );

Procedure Expand_Key(wordsInKey, rounds: Byte; roundKey: PByteArray; key: PByteArray);
Var i, j, k: Cardinal;
    u8tmp: Byte;
    tempa: Array[0..3] of Byte;
Begin
  For i := 0 To wordsInKey - 1
    Do
      Begin
        RoundKey^[(i * 4) + 0] := key^[(i * 4) + 0];
        RoundKey^[(i * 4) + 1] := key^[(i * 4) + 1];
        RoundKey^[(i * 4) + 2] := key^[(i * 4) + 2];
        RoundKey^[(i * 4) + 3] := key^[(i * 4) + 3];
      End;

  For i := wordsInKey To COLUMNS * (rounds + 1) - 1
    Do
      Begin
        k := (i - 1) * 4;
        tempa[0] := RoundKey^[k + 0];
        tempa[1] := RoundKey^[k + 1];
        tempa[2] := RoundKey^[k + 2];
        tempa[3] := RoundKey^[k + 3];

        If i mod wordsInKey = 0
          Then
            Begin
              u8tmp := tempa[0];
              tempa[0] := tempa[1];
              tempa[1] := tempa[2];
              tempa[2] := tempa[3];
              tempa[3] := u8tmp;

              tempa[0] := SBOX[tempa[0]];
              tempa[1] := SBOX[tempa[1]];
              tempa[2] := SBOX[tempa[2]];
              tempa[3] := SBOX[tempa[3]];

              tempa[0] := tempa[0] xor ROUND_CONSTANT[i div wordsInKey];
            End;

        If (wordsInKey = KEY_WORDS_256) And (i mod wordsInKey = 4)
          Then
            Begin
              tempa[0] := SBOX[tempa[0]];
              tempa[1] := SBOX[tempa[1]];
              tempa[2] := SBOX[tempa[2]];
              tempa[3] := SBOX[tempa[3]];
            End;

        j := i * 4;
        k := (i - wordsInKey) * 4;
        RoundKey^[j + 0] := RoundKey^[k + 0] xor tempa[0];
        RoundKey^[j + 1] := RoundKey^[k + 1] xor tempa[1];
        RoundKey^[j + 2] := RoundKey^[k + 2] xor tempa[2];
        RoundKey^[j + 3] := RoundKey^[k + 3] xor tempa[3];
      End;
End;

Procedure AddRoundKey(round: Byte; state: PState; roundKey: PByteArray);
Var i, j: Byte;
Begin
  For I := 0 To 3
    Do For J := 0 to 3
      Do state^[i][j] := state^[i][j] xor roundKey^[(round * COLUMNS * 4) + (i * COLUMNS) + j];
End;

Procedure SubBytes(state: PState);
Var i, j: Byte;
Begin
  For I := 0 To 3
    Do For J := 0 to 3
      Do state^[j][i] := SBOX[state^[j][i]];
End;

Procedure InverseSubBytes(state: PState);
Var i, j: Byte;
Begin
  For I := 0 To 3
    Do For J := 0 to 3
      Do state^[j][i] := RSBOX[state^[j][i]];
End;

Procedure ShiftRows(state: PState);
Var temp: Byte;
Begin
  // Rotate first row 1 columns to left
  temp        := state^[0][1];
  state^[0][1] := state^[1][1];
  state^[1][1] := state^[2][1];
  state^[2][1] := state^[3][1];
  state^[3][1] := temp;

  // Rotate second row 2 columns to left
  temp         := state^[0][2];
  state^[0][2] := state^[2][2];
  state^[2][2] := temp;

  temp         := state^[1][2];
  state^[1][2] := state^[3][2];
  state^[3][2] := temp;

  // Rotate third row 3 columns to left
  temp         := state^[0][3];
  state^[0][3] := state^[3][3];
  state^[3][3] := state^[2][3];
  state^[2][3] := state^[1][3];
  state^[1][3] := temp;
End;

Procedure InverseShiftRows(state: PState);
Var temp: Byte;
Begin
  // Rotate first row 1 columns to right
  temp         := state^[3][1];
  state^[3][1] := state^[2][1];
  state^[2][1] := state^[1][1];
  state^[1][1] := state^[0][1];
  state^[0][1] := temp;

  // Rotate second row 2 columns to right
  temp         := state^[0][2];
  state^[0][2] := state^[2][2];
  state^[2][2] := temp;

  temp         := state^[1][2];
  state^[1][2] := state^[3][2];
  state^[3][2] := temp;

  // Rotate third row 3 columns to right
  temp         := state^[0][3];
  state^[0][3] := state^[1][3];
  state^[1][3] := state^[2][3];
  state^[2][3] := state^[3][3];
  state^[3][3] := temp;
End;

Function xtime(x: Byte): Byte; Inline;
Begin
  Result := ((x shl 1) xor (((x shr 7) and 1) * $1b));
End;

Function Multiply(x, y: Byte): Byte; Inline;
Begin
  Result := (((y and 1) * x) xor
             ((y shr 1 and 1) * xtime(x)) xor
             ((y shr 2 and 1) * xtime(xtime(x))) xor
             ((y shr 3 and 1) * xtime(xtime(xtime(x)))) xor
             ((y shr 4 and 1) * xtime(xtime(xtime(xtime(x))))));
End;

Procedure MixColumns(state: PState);
Var i, tmp, tm, t: Byte;
Begin
  For i := 0 To 3
    Do
      Begin
        t   := state^[i][0];
        tmp := state^[i][0] xor state^[i][1] xor state^[i][2] xor state^[i][3];
        tm  := state^[i][0] xor state^[i][1]; tm := xtime(tm); state^[i][0] := state^[i][0] xor tm xor tmp;
        tm  := state^[i][1] xor state^[i][2]; tm := xtime(tm); state^[i][1] := state^[i][1] xor tm xor tmp;
        tm  := state^[i][2] xor state^[i][3]; tm := xtime(tm); state^[i][2] := state^[i][2] xor tm xor tmp;
        tm  := state^[i][3] xor t;            tm := xtime(tm); state^[i][3] := state^[i][3] xor tm xor tmp;
      End;
End;

Procedure InverseMixColumns(state: PState);
Var i, a, b, c, d: Byte;
Begin
  For i := 0 To 3
    Do
      Begin
        a   := state^[i][0];
        b   := state^[i][1];
        c   := state^[i][2];
        d   := state^[i][3];

        state^[i][0] := Multiply(a, $0e) xor Multiply(b, $0b) xor Multiply(c, $0d) xor Multiply(d, $09);
        state^[i][1] := Multiply(a, $09) xor Multiply(b, $0e) xor Multiply(c, $0b) xor Multiply(d, $0d);
        state^[i][2] := Multiply(a, $0d) xor Multiply(b, $09) xor Multiply(c, $0e) xor Multiply(d, $0b);
        state^[i][3] := Multiply(a, $0b) xor Multiply(b, $0d) xor Multiply(c, $09) xor Multiply(d, $0e);
      End;
End;

Procedure Cipher(rounds: Byte; state: PState; roundKey: PByteArray);
Var round: Byte;
Begin
  AddRoundKey(0, state, roundKey);
  round := 1;
  While True
    Do
      Begin
        SubBytes(state);
        ShiftRows(state);
        If round = rounds
          Then Break;
        MixColumns(state);
        AddRoundKey(round, state, roundKey);
        Inc(round);
      End;
  AddRoundKey(rounds, state, roundKey);
End;

Procedure InverseCipher(rounds: Byte; state: PState; roundKey: PByteArray);
Var round: Byte;
Begin
  AddRoundKey(rounds, state, roundKey);
  round := rounds - 1;
  While True
    Do
      Begin
        InverseShiftRows(state);
        InverseSubBytes(state);
        AddRoundKey(round, state, roundKey);
        If round = 0
          Then Break;
        InverseMixColumns(state);
        Dec(round);
      End;
End;

Procedure XORwithIV(buffer, iv: PByteArray); Inline;
Var i: Byte;
Begin
  For i := 0 to AES_BLOCKLEN - 1
    Do buffer^[i] := buffer^[i] xor iv^[i];
End;

{==============================================================================}
{ AES-128                                                                      }
{==============================================================================}
Procedure AES_128_init_ctx(ctx: PAES_128_Ctx; key: Pointer);
Begin
  Expand_Key(KEY_WORDS_128, ROUNDS_128, PByteArray(@ctx^.RoundKey), PByteArray(key));
End;

Procedure AES_128_init_ctx_iv(ctx: PAES_128_Ctx; key, iv: Pointer);
Begin
  Expand_Key(KEY_WORDS_128, ROUNDS_128, PByteArray(@ctx^.RoundKey), PByteArray(key));
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_128_ctx_set_iv(ctx: PAES_128_Ctx; iv: Pointer);
Begin
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_128_ECB_encrypt(ctx: PAES_128_Ctx; buf: Pointer);
Begin
  Cipher(ROUNDS_128, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_128_ECB_decrypt(ctx: PAES_128_Ctx; buf: Pointer);
Begin
  InverseCipher(ROUNDS_128, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_128_CBC_encrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; iv: Pointer;
Begin
  i := 0;
  iv := @ctx^.iv;
  While i < length
    Do
      Begin
        XORwithIV(buf, iv);
        Cipher(ROUNDS_128, PState(buf), PByteArray(@ctx^.RoundKey));
        iv := buf;
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
  AES_128_ctx_set_iv(ctx, iv);
End;

Procedure AES_128_CBC_decrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; storedIv: Array[0..AES_BLOCKLEN - 1] of Byte;
Begin
   i := 0;
   While i < length
    Do
      Begin
        Move(PByteArray(buf)^[0], storedIv[0], AES_BLOCKLEN);
        InverseCipher(ROUNDS_128, PState(buf), PByteArray(@ctx^.RoundKey));
        XORwithIV(buf, @ctx^.iv);
        AES_128_ctx_set_iv(ctx, @storedIv);
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
End;

Procedure AES_128_CTR_xcrypt_buffer(ctx: PAES_128_Ctx; buf: Pointer; length: Integer);
Var buffer: Array[0..AES_BLOCKLEN - 1] of Byte;
    i: Cardinal;
    bi: Integer;
Begin
  bi := AES_BLOCKLEN;
  For I := 0 To length - 1
    Do
      Begin
        If bi = AES_BLOCKLEN
          Then
            Begin
              Move(ctx^.Iv[0], buffer[0], AES_BLOCKLEN);
              Cipher(ROUNDS_128, PState(@buffer), PByteArray(@ctx^.RoundKey));
              For bi := AES_BLOCKLEN - 1 DownTo 0
                Do
                  Begin
                    If ctx^.Iv[bi] = 255
                      Then
                        Begin
                          ctx^.Iv[bi] := 0;
                          Continue;
                        End;
                    Inc(ctx^.Iv[bi]);
                    Break;
                  End;
              bi := 0;
            End;

        TByteArray(buf^)[i] := TByteArray(buf^)[i] xor buffer[bi];
        Inc(bi);
      End;
End;
{==============================================================================}
{ AES-128                                                                      }
{==============================================================================}
Procedure AES_192_init_ctx(ctx: PAES_192_Ctx; key: Pointer);
Begin
  Expand_Key(KEY_WORDS_192, ROUNDS_192, PByteArray(@ctx^.RoundKey), PByteArray(key));
End;

Procedure AES_192_init_ctx_iv(ctx: PAES_192_Ctx; key, iv: Pointer);
Begin
  Expand_Key(KEY_WORDS_192, ROUNDS_192, PByteArray(@ctx^.RoundKey), PByteArray(key));
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_192_ctx_set_iv(ctx: PAES_192_Ctx; iv: Pointer);
Begin
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_192_ECB_encrypt(ctx: PAES_192_Ctx; buf: Pointer);
Begin
  Cipher(ROUNDS_192, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_192_ECB_decrypt(ctx: PAES_192_Ctx; buf: Pointer);
Begin
  InverseCipher(ROUNDS_192, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_192_CBC_encrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; iv: Pointer;
Begin
  i := 0;
  iv := @ctx^.iv;
  While i < length
    Do
      Begin
        XORwithIV(buf, iv);
        Cipher(ROUNDS_192, PState(buf), PByteArray(@ctx^.RoundKey));
        iv := buf;
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
  AES_192_ctx_set_iv(ctx, iv);
End;

Procedure AES_192_CBC_decrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; storedIv: Array[0..AES_BLOCKLEN - 1] of Byte;
Begin
   i := 0;
   While i < length
    Do
      Begin
        Move(PByteArray(buf)^[0], storedIv[0], AES_BLOCKLEN);
        InverseCipher(ROUNDS_192, PState(buf), PByteArray(@ctx^.RoundKey));
        XORwithIV(buf, @ctx^.iv);
        AES_192_ctx_set_iv(ctx, @storedIv);
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
End;

Procedure AES_192_CTR_xcrypt_buffer(ctx: PAES_192_Ctx; buf: Pointer; length: Integer);
Var buffer: Array[0..AES_BLOCKLEN - 1] of Byte;
    i: Cardinal;
    bi: Integer;
Begin
  bi := AES_BLOCKLEN;
  For I := 0 To length - 1
    Do
      Begin
        If bi = AES_BLOCKLEN
          Then
            Begin
              Move(ctx^.Iv[0], buffer[0], AES_BLOCKLEN);
              Cipher(ROUNDS_192, PState(@buffer), PByteArray(@ctx^.RoundKey));
              For bi := AES_BLOCKLEN - 1 DownTo 0
                Do
                  Begin
                    If ctx^.Iv[bi] = 255
                      Then
                        Begin
                          ctx^.Iv[bi] := 0;
                          Continue;
                        End;
                    Inc(ctx^.Iv[bi]);
                    Break;
                  End;
              bi := 0;
            End;

        TByteArray(buf^)[i] := TByteArray(buf^)[i] xor buffer[bi];
        Inc(bi);
      End;
End;


{==============================================================================}
{ AES-256                                                                      }
{==============================================================================}
Procedure AES_256_init_ctx(ctx: PAES_256_Ctx; key: Pointer);
Begin
  Expand_Key(KEY_WORDS_256, ROUNDS_256, PByteArray(@ctx^.RoundKey), PByteArray(key));
End;

Procedure AES_256_init_ctx_iv(ctx: PAES_256_Ctx; key, iv: Pointer);
Begin
  Expand_Key(KEY_WORDS_256, ROUNDS_256, PByteArray(@ctx^.RoundKey), PByteArray(key));
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_256_ctx_set_iv(ctx: PAES_256_Ctx; iv: Pointer);
Begin
  Move(PByteArray(iv)^[0], ctx^.Iv[0], AES_BLOCKLEN);
End;

Procedure AES_256_ECB_encrypt(ctx: PAES_256_Ctx; buf: Pointer);
Begin
  Cipher(ROUNDS_256, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_256_ECB_decrypt(ctx: PAES_256_Ctx; buf: Pointer);
Begin
  InverseCipher(ROUNDS_256, PState(buf), PByteArray(@ctx^.RoundKey));
End;

Procedure AES_256_CBC_encrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; iv: Pointer;
Begin
  i := 0;
  iv := @ctx^.iv;
  While i < length
    Do
      Begin
        XORwithIV(buf, iv);
        Cipher(ROUNDS_256, PState(buf), PByteArray(@ctx^.RoundKey));
        iv := buf;
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
  AES_256_ctx_set_iv(ctx, iv);
End;

Procedure AES_256_CBC_decrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);
Var i: Cardinal; storedIv: Array[0..AES_BLOCKLEN - 1] of Byte;
Begin
   i := 0;
   While i < length
    Do
      Begin
        Move(PByteArray(buf)^[0], storedIv[0], AES_BLOCKLEN);
        InverseCipher(ROUNDS_128, PState(buf), PByteArray(@ctx^.RoundKey));
        XORwithIV(buf, @ctx^.iv);
        AES_256_ctx_set_iv(ctx, @storedIv);
        Inc(i, AES_BLOCKLEN);
        buf := Pointer(NativeUInt(buf) + AES_BLOCKLEN);
      End;
End;

Procedure AES_256_CTR_xcrypt_buffer(ctx: PAES_256_Ctx; buf: Pointer; length: Integer);
Var buffer: Array[0..AES_BLOCKLEN - 1] of Byte;
    i: Cardinal;
    bi: Integer;
Begin
  bi := AES_BLOCKLEN;
  For I := 0 To length - 1
    Do
      Begin
        If bi = AES_BLOCKLEN
          Then
            Begin
              Move(ctx^.Iv[0], buffer[0], AES_BLOCKLEN);
              Cipher(ROUNDS_256, PState(@buffer), PByteArray(@ctx^.RoundKey));
              For bi := AES_BLOCKLEN - 1 DownTo 0
                Do
                  Begin
                    If ctx^.Iv[bi] = 255
                      Then
                        Begin
                          ctx^.Iv[bi] := 0;
                          Continue;
                        End;
                    Inc(ctx^.Iv[bi]);
                    Break;
                  End;
              bi := 0;
            End;

        TByteArray(buf^)[i] := TByteArray(buf^)[i] xor buffer[bi];
        Inc(bi);
      End;
End;

Begin

End.
