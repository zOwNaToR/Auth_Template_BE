using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EmailSender;
public interface IEmailSender
{
    Task SendAsync(string from, string to, string subject, string html);
    Task SendAsync(string from, IEnumerable<string> to, string subject, string html);
    //void Send(string from, IEnumerable<string> to, string subject, string html);
}
