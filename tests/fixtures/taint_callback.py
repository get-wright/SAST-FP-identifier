# Taint flow patterns: for-loops, map, comprehensions

def for_loop_taint(request):
    items = request.args.getlist("items")
    for item in items:
        cursor.execute(f"SELECT * FROM t WHERE name = '{item}'")

def map_taint(request):
    names = request.args.getlist("names")
    queries = list(map(lambda n: f"SELECT * FROM users WHERE name = '{n}'", names))
    for q in queries:
        cursor.execute(q)

def comprehension_taint(request):
    ids = request.args.getlist("ids")
    queries = [f"DELETE FROM t WHERE id = {i}" for i in ids]
    for q in queries:
        cursor.execute(q)

def for_loop_sanitized(request):
    items = request.args.getlist("items")
    for item in items:
        safe = escape(item)
        output(f"<div>{safe}</div>")

def nested_function_taint(request):
    data = request.form.get("data")
    def process():
        return eval(data)
    process()
