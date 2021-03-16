using Gabriel.Cat.S.Extension;
using System;
using System.Collections.Generic;
using System.Text;

namespace Gabriel.Cat.S.Seguretat
{
    internal delegate int IndexPerdutMethod<T>(Context<T> data, byte[] password, int level) where T:unmanaged;
    public static class PerdutMethod
    {
        public static Context<T> InitPerdut<T>(this T[] data,bool encryptOrDecrypt=true) where T:unmanaged
        {
            return new Context<T>
            {
                Input=data,
                Output=data.Convert((i)=>i),
                OutputIndex=encryptOrDecrypt?0:data.Length-1
            };
        }
        public static Context<T> EncryptPerdut<T>(this Context<T> data, byte[] password, LevelEncrypt level, StopProcess stopProcess=null) where T : unmanaged
        {
            return DecryptEncrypt(data, password, stopProcess, level, IndexPerdutEncrypt, true);
        }
        public static Context<T> DecryptPerdut<T>(this Context<T> data, byte[] password, LevelEncrypt level, StopProcess stopProcess=null ) where T : unmanaged
        {
            return DecryptEncrypt(data, password, stopProcess, level, IndexPerdutDecrypt, false);
        }
        static Context<T> DecryptEncrypt<T>(this Context<T> data,byte[] password,StopProcess stopProcess,LevelEncrypt level,IndexPerdutMethod<T> metodo,bool encryptOrDecrypt) where T:unmanaged
        {
            T aux;
            int index;
            int levelEncrypt = (int)level;
            int suma = encryptOrDecrypt ? 1 : -1;
            if(Equals(stopProcess,null))
            {
                stopProcess = new StopProcess();
            }
            unsafe
            {
                T* ptrIn, ptrOut;
                fixed(T* ptIn = data.Input, ptOut = data.Output)
                {
                    ptrIn = ptIn + data.InputIndex;
                    ptrOut = ptOut + data.OutputIndex;
                    for(;!data.Acabado && stopProcess.Continue; data.OutputIndex+=suma)
                    {
                        index = metodo(data, password, levelEncrypt);
                        aux = data.Output[index];
                        data.Output[index] = data.Output[data.OutputIndex];
                        data.Output[data.OutputIndex] = aux;
                    }
                }


            }

            return data;
        }

        static int IndexPerdutEncrypt<T>(Context<T> context,byte[] password,int level) where T:unmanaged
        {
            return 0;
        }
        static int IndexPerdutDecrypt<T>(Context<T> context, byte[] password, int level) where T : unmanaged
        {
            return 0;
        }

    }
}
