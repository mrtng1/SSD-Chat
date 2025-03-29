namespace ChatServer.DTOs;

public class EncryptedMessageDto
{
    public string RecipientId { get; set; }
    public byte[] Ciphertext { get; set; }
    public byte[] Nonce { get; set; }
    public byte[] Tag { get; set; }
    public byte[] Signature { get; set; }
}

public class Message
{
    public string Sender { get; set; }
    public string SenderName { get; set; }
    public string SenderPublicKey { get; set; }
    public string Recipient { get; set; }
    public string Content { get; set; }
    public string EncryptionIv { get; set; }
}