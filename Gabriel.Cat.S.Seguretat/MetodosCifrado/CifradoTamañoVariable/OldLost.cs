namespace Gabriel.Cat.S.Seguretat{

public static class OldLost{

public static byte[] Encrypt(byte[] data,byte[] password){
byte[] dataEncrypted=new byte[data.Length+EncryptDecrypt.BytesChangeDefault.Length+(password.Length-((data.Length+EncryptDecrypt.BytesChangeDefault.Length)/password.Length))];
int[] posiciones=GetPosPassword(password);
int longitudColumna=dataEncrypted.Length/posiciones.Length;    
long pos=0;
byte[] aux=new byte[1];    
unsafe{
byte* ptrAux;
byte* ptrMarcaFin;    
byte* ptrData;
byte* ptrEncrypted;    
fixed(byte* ptData=data)    
{
    ptrData=ptData;
    fixed(byte* ptEncrypted=dataEncrypted){
    
        ptrEncrypted=ptEncrypted;
         fixed(byte* ptAux=aux){
    
        ptrAux=ptAux;
        fixed(byte* ptMarcaFin=EncryptDecrypt.BytesChangeDefault){
    
        ptrMarcaFin=ptMarcaFin;
        for(int i=0;i<data.Length;i+=password.Length){
        PonFila(ptrEncrypted,ptrData,longitudColumnas,posicionesContraseña,pos);
            ptrEncrypted+=password.Length;
            pos+=password.Length;
            ptrData+=password.Length;
        }
        for(int i=0;i<EncryptDecrypt.BytesChangeDefault.Length;i+=password.Length))
        {
            PonFila(ptrEncrypted,ptrMarcaFin,longitudColumnas,posicionesContraseña,pos);
            ptrEncrypted+=password.Length;
            pos+=password.Length;
            ptrMarcaFin+=password.Length;
        }
        for(int i=0,f=dataEncrypted.Length-(data.Length+EncryptDecrypt.BytesChangeDefault.Length);i<f;i++)
        {
            *ptrAux=(byte)MiRandom.Next(byte.MaxValue);
            PonFila(ptrEncrypted,ptrAux,longitudColumnas,posicionesContraseña,pos,1);
            ptrEncrypted++;
            pos++;
        }
    }
         }}

}
static unsafe void PonFila(byte* ptrOut,byte* ptrIn,int longitudColumnas,int[] posicionesContraseña,long pos,int linea=-1){
byte* aux;
 if(linea==-1)
     linea=posicionesContraseña.Length;
    //pongo la fila
    for(int i=0;i<linea;i++)
    {
        aux=ptrOut+posicionesContraseña[pos/longitudColumnas];
        *aux=*ptrIn;
        
        pos++;
        ptrIn++;
        
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
