using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EmailSender;
public interface IEmailSender
{
    void Send(string from, string to, string subject, string html);
    //void Send(string from, IEnumerable<string> to, string subject, string html);
}
