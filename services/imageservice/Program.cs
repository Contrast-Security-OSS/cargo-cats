using Newtonsoft.Json;
using System.Drawing;
using System.Text.Encodings.Web;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

// Force vulnerable assemblies to load at runtime
Console.WriteLine("[DEBUG] Loading vulnerable dependencies for security testing...");
var _ = JsonConvert.SerializeObject(new { loaded = "Newtonsoft.Json" });
var __ = JavaScriptEncoder.Default;
var ___ = typeof(Bitmap).FullName;
var ____ = typeof(SqlConnection).FullName;
Console.WriteLine("[DEBUG] Vulnerable dependencies loaded successfully");

// Ensure the uploads directory exists
var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
Directory.CreateDirectory(uploadsPath);
Console.WriteLine($"[DEBUG] Image service starting. Uploads directory: {uploadsPath}");

app.MapGet("/", () =>
{
    Console.WriteLine("[DEBUG] GET / - Retrieving photo list");
    try
    {
        // Get all image files from the uploads directory
        var imageExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp" };
        var imageFiles = Directory.GetFiles(uploadsPath)
            .Where(file => imageExtensions.Contains(Path.GetExtension(file).ToLower()))
            .Select(file => new
            {
                filename = Path.GetFileName(file),
                path = Path.GetFileName(file),
                size = new FileInfo(file).Length,
                created = new FileInfo(file).CreationTime
            })
            .OrderByDescending(f => f.created)
            .ToList();

        Console.WriteLine($"[DEBUG] Found {imageFiles.Count} photos in uploads directory");
        return Results.Ok(new
        {
            message = "Image Service - Saved Photos",
            totalPhotos = imageFiles.Count,
            photos = imageFiles
        });
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[ERROR] Failed to retrieve photos: {ex.Message}");
        return Results.Problem($"Error retrieving photos: {ex.Message}");
    }
});

app.MapPost("/savephoto", async (IFormFile file) =>
{
    Console.WriteLine($"[DEBUG] POST /savephoto - Received file upload request");
    if (file == null || file.Length == 0)
    {
        Console.WriteLine("[DEBUG] No file provided or file is empty");
        return Results.BadRequest("No file provided or file is empty");
    }

    var fileName = file.FileName;
    var filePath = Path.Combine(uploadsPath, fileName);
    Console.WriteLine($"[DEBUG] Saving file: {fileName} to {filePath} (size: {file.Length} bytes)");
    
    using (var stream = new FileStream(filePath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }

    Console.WriteLine($"[DEBUG] Successfully saved file: {fileName}");
    // Return just the filename, not the full path
    return Results.Ok(new { path = fileName });
}).DisableAntiforgery();

app.MapGet("/getphoto", (string path) =>
{
    Console.WriteLine($"[DEBUG] GET /getphoto - Requested path: {path}");
    if (string.IsNullOrEmpty(path))
    {
        Console.WriteLine("[DEBUG] Path parameter is empty or null");
        return Results.BadRequest("Path parameter is required");
    }
    var fullPath = Path.Combine(uploadsPath, path);
    Console.WriteLine($"[DEBUG] Full file path: {fullPath}");

    if (!File.Exists(fullPath))
    {
        Console.WriteLine($"[DEBUG] File not found: {fullPath}");
        return Results.NotFound("File not found");
    }

    // Determine content type based on file extension
    var contentType = Path.GetExtension(fullPath).ToLower() switch
    {
        ".jpg" or ".jpeg" => "image/jpeg",
        ".png" => "image/png",
        ".gif" => "image/gif",
        ".bmp" => "image/bmp",
        ".webp" => "image/webp",
        ".txt" => "text/plain",
        ".json" => "application/json",
        ".xml" => "application/xml",
        ".config" => "text/plain",
        _ => "application/octet-stream"
    };
    Console.WriteLine($"[DEBUG] Serving file with content type: {contentType}");
    var fileBytes = File.ReadAllBytes(fullPath);
    Console.WriteLine($"[DEBUG] File size: {fileBytes.Length} bytes");
    return Results.File(fileBytes, contentType);
});

Console.WriteLine("[DEBUG] Starting image service application...");
app.Run();
