namespace Gabriel.Cat.S.Seguretat{

public static class OldLost{

public static byte[] Encrypt(byte[] data,byte[] password){
byte[] dataEncrypted=new byte[data.Length+EncryptDecrypt.BytesChangeDefault.Length+(password.Length-((data.Length+EncryptDecrypt.BytesChangeDefault.Length)/password.Length))];
int[] posiciones=GetPosPassword(password);
int longitudColumna=dataEncrypted.Length/posiciones.Length;    
int pos=0;
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
static unsafe void PonFila(byte* ptrOut,byte* ptrIn,int longitudColumnas,int[] posicionesContraseña,int pos,int linea=-1){
byte* aux;
 if(linea==-1)
     linea=posicionesContraseña.Length;
    //pongo la fila
    for(int i=0;i<linea;i++)
    {
        aux=ptrOut+posicionesContraseña[pos%longitudColumnas];
        *aux=*ptrIn;
        
        pos++;
        ptrIn++;
        
    }

}    



    }
return dataEncrypted;
}
public static byte[] Decrypt(byte[] data,byte[] password){

    byte[] decrypted=new byte[data.Length];
    int[] posicionesPassword=GetPosPassword(password);

    int longitudColumna=data.Length/password.Length;
    unsafe{
     byte* ptrData;
     byte* ptrDecrypted;
     
     fixed(byte* ptData=data)
     {
      
         ptrData=ptData;
         fixed(byte* ptDecrypted=decrypted){
         ptrDecrypted=ptDecrypted;
             for(int i=0;i<data.Length;i++,ptrData+=password.Length){//ahora no se desde el navegador si se puede poner asi...
                 *ptrDecrypted=*(ptrData+(posicionesContraseña[i%longitudColumnas]));
                 ptrDecrypted++;
                 
                 
             }
         
         
         
         }
         
         
     }
        
        
        
        
    }
    
    
    
    return decrypted.SubArray(decrypted.SearchArray(EncryptDecrypt.BytesChangeDefault));//si se pudiese empezar a buscar de atras hacia adelante mejor
    
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
