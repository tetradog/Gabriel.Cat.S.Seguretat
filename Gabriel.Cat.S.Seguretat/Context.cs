namespace Gabriel.Cat.S.Seguretat
{
    public class Context<T> where T:unmanaged
    {
        public T[] Input { get; set; }
        public T[] Output { get; set; }

        public long InputIndex { get; set; } = 0;
        public long OutputIndex { get; set; } = 0;
        public bool Acabado => InputIndex == Input.Length;

    }
}
