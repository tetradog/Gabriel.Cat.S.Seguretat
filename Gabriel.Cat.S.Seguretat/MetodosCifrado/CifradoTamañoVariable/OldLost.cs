namespace Gabriel.Cat.S.Seguretat{

public static class OldLost{

public static byte[] Encrypt(byte[] data,byte[] password){
byte[] dataEncrypted=new byte[data.Length+EncryptDecrypt.BytesChangeDefault.Length+(password.Length-((data.Length+EncryptDecrypt.BytesChangeDefault.Length)/password.Length))];
int[] posiciones=GetPosPassword(password);
long pos=0;
unsafe{
byte* ptrData;
byte* ptrEncrypted;    
fixed(byte* ptData=data)    
{
    ptrData=ptData;
    fixed(byte* ptEncrypted=dataEncrypted){
    
        ptrEncrypted=ptEncrypted;
        for(int i=0;i<data.Length;i++){
        
        }
        for(int i=0;i<EncryptDecrypt.BytesChangeDefault.Length;i++)
        {
            
        }
        for(int i=0,f=dataEncrypted.Length-(data.Length+EncryptDecrypt.BytesChangeDefault.Length);i<f;i++)
        {
            
        }
    }

}



    }
return dataEncrypted;
}
static int[] GetPosPassword(byte[] password){
//devuelvo la posicion por orden y orden de aparición
int[] pos=new int[password.Length];
int puestos=0;

for(int i=0,f=byte.MaxValue,fin=password.Length-1;i<f&&puestos<fin;i++){
for(int j=0;j<password.Length&&puestos<fin;j++)
{
    if(i==password[j])
      pos[puestos++]=j;
}
}

return pos;
}




}


}
