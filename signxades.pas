unit SignXAdES;

interface

uses
  SysUtils, Classes, XMLDoc, XMLIntf, System.Hash, System.NetEncoding,
  IdSSLOpenSSLHeaders;

procedure SignFileXAdES(const InputFile, OutputFile, CertFile, KeyFile: string);

implementation

function LoadPrivateKey(const KeyFile: string): PEVP_PKEY;
var
  Bio: PBIO;
begin
  Bio := BIO_new_file(PAnsiChar(AnsiString(KeyFile)), 'r');
  if Bio = nil then
    raise Exception.CreateFmt('Unable to open key file %s', [KeyFile]);
  Result := PEM_read_bio_PrivateKey(Bio, nil, nil, nil);
  BIO_free(Bio);
  if Result = nil then
    raise Exception.Create('Failed to read private key');
end;

function SignDigest(const Digest: TBytes; PKey: PEVP_PKEY): TBytes;
var
  Ctx: EVP_MD_CTX;
  SigLen: Cardinal;
begin
  EVP_MD_CTX_init(@Ctx);
  try
    if EVP_SignInit(@Ctx, EVP_sha256()) <> 1 then
      raise Exception.Create('EVP_SignInit failed');
    if (Length(Digest) > 0) and (EVP_SignUpdate(@Ctx, @Digest[0], Length(Digest)) <> 1) then
      raise Exception.Create('EVP_SignUpdate failed');
    SetLength(Result, EVP_PKEY_size(PKey));
    if EVP_SignFinal(@Ctx, @Result[0], SigLen, PKey) <> 1 then
      raise Exception.Create('EVP_SignFinal failed');
    SetLength(Result, SigLen);
  finally
    EVP_MD_CTX_cleanup(@Ctx);
  end;
end;

procedure AddSimpleXAdES(const Doc: IXMLDocument; const Digest, Signature,
  Certificate: string);
var
  SigNode: IXMLNode;
begin
  SigNode := Doc.DocumentElement.AddChild('Signature');
  SigNode.AddChild('DigestValue').Text := Digest;
  SigNode.AddChild('SignatureValue').Text := Signature;
  SigNode.AddChild('Certificate').Text := Certificate;
end;

procedure SignFileXAdES(const InputFile, OutputFile, CertFile, KeyFile: string);
var
  XML: IXMLDocument;
  Data: TBytes;
  DigestBytes, SignatureBytes: TBytes;
  PKey: PEVP_PKEY;
begin
  XML := LoadXMLDocument(InputFile);
  Data := TFile.ReadAllBytes(InputFile);
  DigestBytes := THashSHA2.GetHashBytes(Data);

  PKey := LoadPrivateKey(KeyFile);
  try
    SignatureBytes := SignDigest(DigestBytes, PKey);
  finally
    EVP_PKEY_free(PKey);
  end;

  AddSimpleXAdES(XML,
    TNetEncoding.Base64.EncodeBytesToString(DigestBytes),
    TNetEncoding.Base64.EncodeBytesToString(SignatureBytes),
    TFile.ReadAllText(CertFile));

  XML.SaveToFile(OutputFile);
end;

end.
