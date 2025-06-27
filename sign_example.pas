program SignExample;

{$APPTYPE CONSOLE}

uses
  SysUtils, SignXAdES;

begin
  try
    SignFileXAdES('input.xml', 'signed.xml', 'mycert.pem', 'mykey.pem');
    Writeln('Document signed successfully.');
  except
    on E: Exception do
      Writeln('Error signing document: ', E.Message);
  end;
end.
