using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
// Este es un servidor web con autenticación.
// Accedemos a la página  http://localhost:8080/ y nos pide usuario y clave
// si damos usuario y clave válido nos permite acceder al recurso

class Program
{
    // declaramos usuario y clave válidos
    static readonly Dictionary<string, string> validUsers = new()
    {
        { "admin", "password123" }
    };
    
    // Creamos un hash para guardar las sesiones
    static readonly HashSet<string> validSessions = new();

    static async Task Main()
    {
        // Creamos el listener que espera la conexión del cliente
        TcpListener listener = new(IPAddress.Loopback, 8080);
        listener.Start();
        Console.WriteLine("Listening on http://localhost:8080/");

        while (true)
        {
            // Para cada cliente que se conecte le pasamos un ClientHandler que lo atienda
            var client = await listener.AcceptTcpClientAsync();
            _ = Task.Run(() => HandleClientAsync(client));
        }
    }

    static async Task HandleClientAsync(TcpClient client)
    {
        // El client handler es un servidor web minimalista
        using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII);
        using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };
        
        // Prepara unas estructuras
        string line;
        var request = new List<string>();
        // y lee líneas del lector de stream hasta que haya algo
        while (!string.IsNullOrWhiteSpace(line = await reader.ReadLineAsync()))
            request.Add(line);
        // Si no hay solicitudes termina (suponemos que el garbage collection se encarga de terminar la conexión)
        if (request.Count == 0)
            return;
        // Mostramos la solicitud recibida 
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> REQUEST: <<<<<<<<<<<<<<<<<<<");
        foreach (var h in request) Console.WriteLine(h);
        // parseamos la solicitud. Extrae la primer línea "GET /index.html HTTP/1.1 ."
        string requestLine = request[0];
        // buscamos la primer línea que tenga autorización .... o nulo ...
        string? authorization = request.FirstOrDefault(h => h.StartsWith("Authorization: "));
        // buscamos la galletita ... y la extraemos ...
        string? cookie = request.FirstOrDefault(h => h.StartsWith("Cookie: "));
        // cortamos la cadena y la convertimos en un array de cadenas separados en los espacios ...
        // toma "GET /index.html HTTP/1.1." y lo convierte en ["GET", "/index.html", "HTTP/1.1", "."] y extrae el segundo elemento (posición 1) 
        string path = requestLine.Split(' ')[1]; // path = "/index.html"
        // todavía no se autenticó
        bool authenticated = false;

        // Verificamos la cookie session
        if (cookie != null && cookie.Contains("sessionid="))
        {
            // Si hay una galletita y coincide con la que tengo en mi base de datos de sesiones
            var sid = cookie.Split("sessionid=")[1].Split(';')[0].Trim(); // extrae el sessionid de la cookie
            if (validSessions.Contains(sid))  // verifica si está 
                authenticated = true; // entonces está autenticado
        }

        // Verificar la autenticación básica. Si no está autenticado (no tiene galletita...) pero tiene user:pass
        if (!authenticated && authorization != null)
        {
            // Un Basic auth header es del tipo: "Authorization: Basic [encoded_string]"
            var encoded = authorization.Split(' ')[2];  // 0:"Authorization:", 1:"Basic", 2:"[encoded_string]" <= Se extrae este ...
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); // Acá obtenemos "username:password"
            var parts = decoded.Split(':'); // Separamos 0:"username", 1:"password"
            // A ver si están ...
            if (parts.Length == 2 && validUsers.TryGetValue(parts[0], out var pw) && pw == parts[1])
            {
                // Si sí están ...
                authenticated = true;

                // Generamos un session ID y lo guardamos
                var sessionId = Guid.NewGuid().ToString();
                validSessions.Add(sessionId);
                // y le respondemos con la galletita ... y redirigimos al recurso ...
                await SendRedirectWithCookie(writer, sessionId);
                return;
            }
        }

        if (!authenticated)   // porque no tiene cookie ni user:pass
        {
            // Respondemos que no tiene acceso
            await SendUnauthorized(writer);
            return;  // y salimos
        }

        // Si está autenticado: Verificamos que pida el index.html
        if (path == "/" || path == "/index.html")   // cualquiera de los dos me da el index
        {
            // y se lo damos
            await SendHtml(writer, "<h1>Welcome!</h1><p>Try <a href='/secret.txt'>secret.txt</a></p>");
        }
        // si pide el archivo
        else if (path == "/secret.txt")
        {
            // se lo damos
            await SendFile(writer, "secret.txt");
        }
        else
        {
            // si pide otra cosa
            await SendNotFound(writer);  // Acá no está ...
        }
    }

    static async Task SendRedirectWithCookie(StreamWriter writer, string sessionId)
    {
        // respondemos con un 302 y lo mandamos a la raíz
        string response =
            "HTTP/1.1 302 Found\r\n" +
            $"Set-Cookie: sessionid={sessionId}; Path=/; HttpOnly\r\n" +
            "Location: /\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";
        await writer.WriteAsync(response);
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> RESPONSE: <<<<<<<<<<<<<<<<<<<");
        Console.WriteLine(response);

    }

    static async Task SendUnauthorized(StreamWriter writer)
    {
        // respondemos no autorizado
        string response =
            "HTTP/1.1 401 Unauthorized\r\n" +
            "WWW-Authenticate: Basic realm=\"MyServer\"\r\n" +
            "Content-Length: 0\r\n" +
            "Connection: close\r\n\r\n";
        await writer.WriteAsync(response);
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> RESPONSE: <<<<<<<<<<<<<<<<<<<");
        Console.WriteLine(response);
    }

    static async Task SendHtml(StreamWriter writer, string html)
    {
        // Mandamos un html
        byte[] htmlBytes = Encoding.UTF8.GetBytes(html);
        string header =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html\r\n" +
            $"Content-Length: {htmlBytes.Length}\r\n" +
            "Connection: close\r\n\r\n";
        await writer.WriteAsync(header);
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> RESPONSE: <<<<<<<<<<<<<<<<<<<");
        Console.WriteLine(header);
        await writer.BaseStream.WriteAsync(htmlBytes, 0, htmlBytes.Length);
    }

    static async Task SendFile(StreamWriter writer, string filePath)
    {
        // mandamos un archivo
        if (!File.Exists(filePath))
        {
            await SendNotFound(writer);
            return;
        }
        
        // Esto sólo para rachivos pequeños. Archivos grandes hay que manejar otras formas
        byte[] content = File.ReadAllBytes(filePath);  // leo la totalidad del archivo a memoria y lo mando de una
        string header =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain\r\n" +
            $"Content-Length: {content.Length}\r\n" +
            "Connection: close\r\n\r\n";
        await writer.WriteAsync(header);
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> RESPONSE: <<<<<<<<<<<<<<<<<<<");
        Console.WriteLine(header);
        await writer.BaseStream.WriteAsync(content, 0, content.Length);
    }

    static async Task SendNotFound(StreamWriter writer)
    {
        // Envío 404 no encontrado ...
        string body = "<h1>404 Not Found</h1>";
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
        string header =
            "HTTP/1.1 404 Not Found\r\n" +
            "Content-Type: text/html\r\n" +
            $"Content-Length: {bodyBytes.Length}\r\n" +
            "Connection: close\r\n\r\n";
        await writer.WriteAsync(header);
        Console.WriteLine(">>>>>>>>>>>>>>>>>>>> RESPONSE: <<<<<<<<<<<<<<<<<<<");
        Console.WriteLine(header);
        await writer.BaseStream.WriteAsync(bodyBytes, 0, bodyBytes.Length);
    }
}
