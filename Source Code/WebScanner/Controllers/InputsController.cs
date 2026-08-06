using Microsoft.AspNetCore.Mvc;
using WebScanner.Data;
using WebScanner.Models;
using System;
using System.Linq;

namespace WebScanner.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class InputsController : ControllerBase
    {
        private readonly AppDbContext _db;

        public InputsController(AppDbContext db)
        {
            _db = db;
        }

        // ✅ إنشاء إدخال جديد
        [HttpPost]
        public IActionResult Create([FromBody] InputField field)
        {
            if (field == null)
                return BadRequest("Invalid input.");

            field.Id = Guid.NewGuid(); // هنا الـ Id GUID
            _db.Inputs.Add(field);
            _db.SaveChanges();

            return CreatedAtAction(nameof(GetById), new { id = field.Id }, field);
        }

        // ✅ جلب كل الإدخالات
        [HttpGet]
        public IActionResult GetAll()
        {
            var inputs = _db.Inputs.ToList();
            return Ok(inputs);
        }

        // ✅ جلب إدخال واحد بالـ Id
        [HttpGet("{id}")]
        public IActionResult GetById(Guid id)
        {
            var input = _db.Inputs.Find(id);
            if (input == null)
                return NotFound();

            return Ok(input);
        }

        // ✅ تحديث إدخال
        [HttpPut("{id}")]
        public IActionResult Update(Guid id, [FromBody] InputField updated)
        {
            var existing = _db.Inputs.Find(id);
            if (existing == null)
                return NotFound();

            existing.Name = updated.Name;
            existing.Type = updated.Type;
            existing.Value = updated.Value;

            _db.SaveChanges();
            return Ok(existing);
        }

        // ✅ حذف إدخال
        [HttpDelete("{id}")]
        public IActionResult Delete(Guid id)
        {
            var input = _db.Inputs.Find(id);
            if (input == null)
                return NotFound();

            _db.Inputs.Remove(input);
            _db.SaveChanges();
            return NoContent();
        }
    }
}
