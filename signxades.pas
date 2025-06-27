unit SignXAdES;

interface

uses
  SysUtils;

procedure SignFileXAdES(const InputFile, OutputFile, CertFile, KeyFile: string);

implementation

uses
  // This example assumes existence of an external XAdES signing library.
  // Replace 'XAdESLib' with the actual unit names provided by your library.
  XAdESLib;

procedure SignFileXAdES(const InputFile, OutputFile, CertFile, KeyFile: string);
var
  Signer: TXAdESSigner;
begin
  Signer := TXAdESSigner.Create;
  try
    Signer.InputFile := InputFile;
    Signer.Certificate := CertFile;
    Signer.PrivateKey := KeyFile;
    Signer.Sign;
    Signer.Save(OutputFile);
  finally
    Signer.Free;
  end;
end;

end.
