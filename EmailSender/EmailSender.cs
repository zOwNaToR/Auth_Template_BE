using Common;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
//using MailKit.Net.Smtp;
//using MailKit.Security;
//using MimeKit;
//using MimeKit.Text;

namespace EmailSender;
public class CustomEmailSender : IEmailSender
{
    private readonly AppSettings _appSettings;

    public CustomEmailSender(IOptions<AppSettings> appSettings)
    {
        _appSettings = appSettings.Value;
    }

    //public void Send(string from, string to, string subject, string html)
    //{
    //    from = string.IsNullOrEmpty(from) ? _appSettings.SMTP.From : from;

    //    // Create message
    //    var email = new MimeMessage();
    //    email.From.Add(MailboxAddress.Parse(from));
    //    email.To.Add(MailboxAddress.Parse(to));
    //    email.Subject = subject;
    //    email.Body = new TextPart(TextFormat.Html)
    //    {
    //        Text = html
    //    };

    //    Send(email);
    //}
    //public void Send(string from, IEnumerable<string> to, string subject, string html)
    //{
    //    from = string.IsNullOrEmpty(from) ? _appSettings.SMTP.From : from;

    //    // Create message
    //    var email = new MimeMessage();
    //    email.From.Add(MailboxAddress.Parse(from));

    //    foreach (var singleTo in to)
    //    {
    //        email.To.Add(MailboxAddress.Parse(singleTo));
    //    }

    //    email.Subject = subject;
    //    email.Body = new TextPart(TextFormat.Html)
    //    {
    //        Text = html
    //    };

    //    Send(email);
    //}

    public void Send(string from, string to, string subject, string html)
    {
        from = string.IsNullOrEmpty(from) ? _appSettings.SMTP.From : from;

        // Create message
        var fromAddress = new MailAddress(from, ".NET Auth");
        var toAddress = new MailAddress(to, to);

        using var email = new MailMessage(fromAddress, toAddress)
        {
            Subject = subject,
            Body = html
        };

        Send(email);
    }
    public void Send(MailMessage email)
    {
        try
        {
            // Send email
            using var smtp = new SmtpClient(_appSettings.SMTP.Host, _appSettings.SMTP.Port)
            {
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Credentials = new NetworkCredential(email.From.Address, _appSettings.SMTP.Password),
                Timeout = 20000,
            };

            smtp.Send(email);
        }
        catch (Exception e)
        {
            throw;
        }
    }

    //public void Send(MimeMessage email)
    //{
    //    try
    //    {
    //        // Send email
    //        using var smtp = new SmtpClient();
    //        smtp.Connect(_appSettings.SMTP.Host, _appSettings.SMTP.Port, SecureSocketOptions.StartTls);
    //        smtp.Authenticate(_appSettings.SMTP.Username, _appSettings.SMTP.Password);
    //        smtp.Send(email);
    //        smtp.Disconnect(true);
    //    }
    //    catch (Exception e)
    //    {
    //        throw;
    //    }
    //}
}
