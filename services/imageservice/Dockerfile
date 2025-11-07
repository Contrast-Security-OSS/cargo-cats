# Use the official .NET Core SDK image to build the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy the project file and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy the rest of the application code
COPY . ./
RUN dotnet publish -c Release -o out

# Use the official .NET Core runtime image for the final image
FROM mcr.microsoft.com/dotnet/aspnet:8.0

# Use app user
USER app

# Copy build artifacts
WORKDIR /app
COPY --chown=app --from=build /app/out .

# Expose port 5001
EXPOSE 5001

# Set the entry point
ENTRYPOINT ["dotnet", "imageservice.dll"]