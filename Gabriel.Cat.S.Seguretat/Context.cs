namespace Gabriel.Cat.S.Seguretat
{
    public class Context<T>
    {
       
        public string Target { get; set; }
        public T[] Input { get; set; }
        public T[] Output { get; set; }

        public long InputIndex { get; set; } = 0;
        public long OutputIndex { get; set; } = 0;
        public bool Acabado
        {
            get
            {
                return Equals(Input, default) ? Output.Length > OutputIndex : Input.Length > InputIndex;
            }
        }


    }
}
