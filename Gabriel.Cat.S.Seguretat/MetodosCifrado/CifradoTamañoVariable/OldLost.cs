namespace Gabriel.Cat.S.Seguretat{

public static class OldLost{
  public static int LenghtEncrypted(byte[] dataDecrypted, byte[] password, LevelEncrypt level, Ordre order)
        {
            return dataDecrypted.Length+EncryptDecrypt.BytesChangeDefault.Length+(password.Length-((dataDecrypted.Length+EncryptDecrypt.BytesChangeDefault.Length)/password.Length));
        }
        public static int LenghtDecrypted(byte[] dataEncrypted, byte[] password, LevelEncrypt level, Ordre order)
        {
          byte[] dataFin;
          int lengthEncrypt;
          unsafe{
          fixed(byte* ptDataEncrypted=dataEncrypted){
          byte*[] pointers=GetPointers(ptDataEncrypted,dataEncrypted.Length,password);
            Gabriel.Cat.S.Utilitats.PointerUtils.Seek(pointers,(dataEncrypted.Length/password.Length)-1);
            dataFin=Gabriel.Cat.S.Utilitats.PointerUtils.ReadLine(pointers);
          }
          }
          
            return dataEncrypted.Length-(dataFin.Length-dataFin.SearchArray(EncryptDecrypt.BytesChangeDefault));
        }
public static byte[] Encrypt(byte[] data,byte[] password, LevelEncrypt level, Ordre order){//level y orden de posicionesPassword
byte[] dataEncrypted=new byte[LengthEncrypted(data,password,level,order)];

int pos=0;
    int lengthFin=dataEncrypted.Length-data.Length;
        unsafe{
            fixed(byte*ptData=data){
                fixed(byte*ptEncrypted=dataEncrypted){
                     fixed(byte*ptFin=EncryptDecrypt.BytesChangeDefault.AddArray(MiRandom.NextBytes(dataEncrypted.Length-EncryptDecrypt.BytesChangeDefault.Length))){
                    byte* ptrEncrypted=ptEncrypted;
            byte*[] dataPointers=GetPointers(ptData,data.Length;password);
                for(int i=0;i<data.Length;i++){
                   *ptrEncrypted=*dataPointers[pos%password.Length];
                    ptrEncrypted++;
                    dataPointers[pos%password.Length]++;
                    pos++;
                }
                    dataPointers=GetPointers(ptFin,lengthFin;password,pos%password.Length);
                    pos=0;
                    for(int i=0,f=lengthFin;i<f;i++)
                    {
                          *ptrEncrypted=*dataPointers[pos%password.Length];
                    ptrEncrypted++;
                    dataPointers[pos%password.Length]++;
                    pos++;
                    }
        }}}}
    return decrypted;

}

public static byte[] Decrypt(byte[] data,byte[] password, LevelEncrypt level, Ordre order){//level y orden de posicionesPassword

    byte[] decrypted=new byte[LengthDecrypted(data,password,level,order)];
int pos=0;
        unsafe{
            fixed(byte*ptData=data){
                fixed(byte*ptDecrypted=decrypted){
                    byte* ptrDecrypted=ptDecrypted;
            byte*[] dataPointers=GetPointers(ptData,data.Length;password);
                for(int i=0;i<decrypted.Length;i++){
                   *ptrDecrypted=*dataPointers[pos%password.Length];
                    ptrDecrypted++;
                    dataPointers[pos%password.Length]++;
                    pos++;
                }
        }}}
    return decrypted;
}
    
static unsafe byte*[] GetPointers(byte* data,int lengthData,byte[] password,int initPos=0){
byte*[] pointers=new byte*[password.Length];
int lengthParte=lengthData/password.Length;  
int pos=0;    
for(int j=byte.MinValue;j<byte.MaxValue&&pos<password.Length;j++)    
for(int i=j==0?initPos:0;i<password.Length&&pos<password.Length;i++)
{
    if(j==password[i]){
    pointers[i]=data;
        data+=lengthParte;
        pos++;
    }

}
    return pointers;
}



}


}
