namespace NetToolBox.HashAuthentication
{
    public sealed class HashKeyEntry
    {
        public string KeyName { get; set; } = null!;
        public string KeyValue { get; set; } = null!;
        public bool IsActive { get; set; }
    }
}
