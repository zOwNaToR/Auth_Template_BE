using Common;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;

namespace EmailSender;
public class CustomEmailSender : IEmailSender
{
    private readonly AppSettings _appSettings;

    public CustomEmailSender(IOptions<AppSettings> appSettings)
    {
        _appSettings = appSettings.Value;
    }

    public void Send(string from, string to, string subject, string html)
    {
        // Create message
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(from));
        email.To.Add(MailboxAddress.Parse(to));
        email.Subject = subject;
        email.Body = new TextPart(TextFormat.Html)
        {
            Text = html
        };

        Send(email);
    }
    public void Send(string from, IEnumerable<string> to, string subject, string html)
    {
        // Create message
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(from));

        foreach (var singleTo in to)
        {
            email.To.Add(MailboxAddress.Parse(singleTo));
        }

        email.Subject = subject;
        email.Body = new TextPart(TextFormat.Html)
        {
            Text = html
        };

        Send(email);
    }

    public void Send(MimeMessage email)
    {
        // Send email
        using var smtp = new SmtpClient();
        smtp.Connect(_appSettings.SMTP.Host, _appSettings.SMTP.Port, SecureSocketOptions.StartTls);
        smtp.Authenticate(_appSettings.SMTP.Username, _appSettings.SMTP.Password);
        smtp.Send(email);
        smtp.Disconnect(true);
    }
}
