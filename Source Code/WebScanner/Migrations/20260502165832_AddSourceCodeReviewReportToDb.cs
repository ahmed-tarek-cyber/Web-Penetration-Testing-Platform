using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScanner.Migrations
{
    /// <inheritdoc />
    public partial class AddSourceCodeReviewReportToDb : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SourceCodeReviewReports",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    FileName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    OriginalFileName = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false, defaultValueSql: "GETUTCDATE()"),
                    CompletedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Status = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    OverallStatus = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    TotalFindings = table.Column<int>(type: "int", nullable: false),
                    FileSize = table.Column<long>(type: "bigint", nullable: false),
                    Engine = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    FindingsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    SeverityBreakdownJson = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SourceCodeReviewReports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SourceCodeReviewReports_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SourceCodeReviewReports_CreatedAt",
                table: "SourceCodeReviewReports",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_SourceCodeReviewReports_UserId",
                table: "SourceCodeReviewReports",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SourceCodeReviewReports");
        }
    }
}
