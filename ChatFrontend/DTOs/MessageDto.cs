namespace ChatServer.DTOs;

public class Message
{
    public string Content { get; set; }
    public string EncryptionIv { get; set; }
    public string Sender { get; set; }
    public string SenderName { get; set; }
    public string SenderPublicKey { get; set; }
    public string Recipient { get; set; }
    public string RecipientPublicKey { get; set; }
}