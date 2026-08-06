using System;
using Microsoft.EntityFrameworkCore;
using WebScanner.Models;

namespace WebScanner.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        // استخدام (= null!;) لإسكات تحذيرات الـ Nullable
        public DbSet<InputField> Inputs { get; set; } = null!;
        public DbSet<ScanReport> Reports { get; set; } = null!;
        public DbSet<Vulnerability> Vulnerabilities { get; set; } = null!;
        public DbSet<User> Users { get; set; } = null!;
        public DbSet<UserEmail> UserEmails { get; set; } = null!;
        public DbSet<SourceCodeReviewReport> SourceCodeReviewReports { get; set; } = null!;
        public DbSet<ChatSession> ChatSessions { get; set; } = null!;
        public DbSet<ChatMessage> ChatMessages { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // ScanReport ↔ Vulnerabilities
            modelBuilder.Entity<ScanReport>().HasKey(r => r.Id);
            modelBuilder.Entity<ScanReport>()
                .HasMany(r => r.Results)
                .WithOne(r => r.ScanReport) // ✅ تم التصحيح: كانت r.Report وأصبحت r.ScanReport
                .HasForeignKey(r => r.ScanReportId)
                .OnDelete(DeleteBehavior.Cascade);

            // Basics
            modelBuilder.Entity<InputField>().HasKey(i => i.Id);
            modelBuilder.Entity<Vulnerability>().HasKey(v => v.Id);

            // Users Configuration
            // (إذا لم يكن لديك كلاس User، قد تحتاج لحذف الأسطر التالية حتى تنشئه)
            modelBuilder.Entity<User>().HasKey(u => u.Id);
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // UserEmails Configuration
            modelBuilder.Entity<UserEmail>().HasKey(e => e.Id);
            modelBuilder.Entity<UserEmail>()
                .Property(e => e.Email)
                .IsRequired()
                .HasMaxLength(320);

            modelBuilder.Entity<UserEmail>()
                .Property(e => e.Source)
                .IsRequired()
                .HasMaxLength(32)
                .HasDefaultValue("Unknown");

            modelBuilder.Entity<UserEmail>()
                .Property(e => e.CreatedAt)
                .HasDefaultValueSql("GETUTCDATE()");

            modelBuilder.Entity<UserEmail>()
                .HasIndex(e => e.Email)
                .IsUnique();

            // SourceCodeReviewReport Configuration
            modelBuilder.Entity<SourceCodeReviewReport>().HasKey(r => r.Id);
            modelBuilder.Entity<SourceCodeReviewReport>()
                .HasIndex(r => r.UserId);
            modelBuilder.Entity<SourceCodeReviewReport>()
                .HasIndex(r => r.CreatedAt);
            modelBuilder.Entity<SourceCodeReviewReport>()
                .Property(r => r.CreatedAt)
                .HasDefaultValueSql("GETUTCDATE()");

            // Chat session/messages
            modelBuilder.Entity<ChatSession>().HasKey(c => c.Id);
            modelBuilder.Entity<ChatMessage>().HasKey(m => m.Id);
            modelBuilder.Entity<ChatSession>()
                .HasMany(c => c.Messages)
                .WithOne(m => m.ChatSession)
                .HasForeignKey(m => m.ChatSessionId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                var cs = Environment.GetEnvironmentVariable("WEBSCANNER_CS")
                         ?? "Server=localhost,1433;Database=ScanlyDB;User Id=sa;Password=YourStrongPass123;TrustServerCertificate=True;Encrypt=False;";
                optionsBuilder.UseSqlServer(cs);
            }
        }
    }
}