using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;

namespace WebScanner.Models
{
   
    public class ScanRequest
    {
        
       
        [Required]
        [Url(ErrorMessage = "Please provide a valid URL starting with http or https.")]
        public string Url { get; set; } = string.Empty;

       
        public Dictionary<string, string> Inputs { get; set; } = new();

        
        public bool UsePost { get; set; } = false;

        
        public Dictionary<string, string> Headers { get; set; } = new();

        
        public Dictionary<string, string> Cookies { get; set; } = new();

        
        public bool IsValid()
        {
            if (string.IsNullOrWhiteSpace(Url))
                return false;

           
            if (!Url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !Url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return false;

           
            if (!Uri.TryCreate(Url, UriKind.Absolute, out var uri))
                return false;

            
            return !string.IsNullOrWhiteSpace(uri.Host);
        }

        
        public HttpRequestMessage ToHttpRequest()
        {
            
            var method = UsePost ? HttpMethod.Post : HttpMethod.Get;
            string finalUrl = Url;

            
            if (!UsePost && Inputs.Count > 0)
            {
                var uri = new UriBuilder(Url);
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                foreach (var kv in Inputs)
                    query[kv.Key] = kv.Value;
                uri.Query = query.ToString();
                finalUrl = uri.ToString();
            }

            var request = new HttpRequestMessage(method, finalUrl);

            
            foreach (var header in Headers)
            {
                if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value))
                {
                   
                    if (UsePost)
                    {
                        request.Content ??= new StringContent("");
                        if (!request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value))
                        {
                          
                        }
                    }
                }
            }

           
            if (Cookies.Count > 0)
            {
                var cookieString = string.Join("; ", Cookies.Select(c => $"{c.Key}={c.Value}"));
                request.Headers.Add("Cookie", cookieString);
            }

            
            if (UsePost && Inputs.Count > 0)
            {
                request.Content = new FormUrlEncodedContent(Inputs);
            }

            return request;
        }
    }
}
