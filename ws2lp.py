#!/usr/bin/python3
# ws2lp

from aiohttp import web
from utils import *; logstart('ws2lp')

class Webhook(SlotsInit):
	hash: str
	secret: str
	response: str | None
	#created: datetime.datetime
	queue: asyncio.Queue

def ensure_get_params(query, *args):
	missing = tuple(i for i in args if not query.get(i))
	if (missing): raise web.HTTPBadRequest(reason=f"""{S(', ').join((f"`{i}'" for i in missing), last=' and ')} parameter{' is' if (len(missing) == 1) else 's are'} required.""")
	return tuple(query[i] for i in args)

routes = web.RouteTableDef()

@routes.post('/create/')
async def handle_create(request):
	hash = randstr(16)

	webhooks = request.app['ws2lp.webhooks']
	if (hash in webhooks): raise web.HTTPConflict(response="Try again.")

	data = {**request.query, **await request.post()}

	webhook = Webhook(
		hash = hash,
		secret = secrets.token_urlsafe(48),
		response = data.get('response'),
		#created = datetime.datetime.now(),
		queue = asyncio.Queue(maxsize=4096),
	)

	webhooks[hash] = webhook
	log(f"Webhooks count increased to {len(webhooks)}.")

	return web.json_response({
		'hash': webhook.hash,
		'secret': webhook.secret,
	})

@routes.post('/delete/')
async def handle_delete(request):
	hash, secret = ensure_get_params(request.query, 'hash', 'secret')

	webhooks = request.app['ws2lp.webhooks']
	try: webhook = webhooks[hash]
	except KeyError as ex: raise web.HTTPNotFound(response="Webhook is not registered.") from ex

	if (secret != webhook.secret): raise web.HTTPForbidden(reason="Incorrect secret.")

	await webhook.queue.join()  # TODO: timeout; TODO: 101 Continue

	try:
		if (webhook is not webhooks[hash]): raise web.HTTPConflict(reason="Webhook changed during the request.")
	except KeyError as ex: raise web.HTTPConflict(reason="Webhook was already deleted.") from ex

	if (secret != webhook.secret): raise web.HTTPForbidden(reason="Incorrect secret.")  # sanity check

	del webhooks[hash]
	log(f"Webhooks count decreased to {len(webhooks)}.")

	return web.Response(status=200)

@routes.get('/wh/{hash:.*}')
@routes.post('/wh/{hash:.*}')
async def handle_wh(request):
	hash = request.match_info['hash'].rstrip('/')

	webhooks = request.app['ws2lp.webhooks']
	try: webhook = webhooks[hash]
	except KeyError as ex: raise web.HTTPNotFound(reason="Webhook is not registered.") from ex

	if (not webhook.response): response = None
	elif (webhook.response[:1] in '"\''):
		response = ast.literal_eval(webhook.response +
		                            webhook.response[0]*(not webhook.response.endswith(webhook.response[0])))
	elif (webhook.response[:1] in '.'):
		try: response = str(operator.attrgetter(webhook.response[1:])(AttrDict(await request.json())))
		except AttributeError: response = ''
	else:
		response = request.headers.get(webhook.response)

	await webhook.queue.put({
		'method': request.method,
		'query': request.query_string,
		'body': await request.text(),
	})

	return web.Response(status=200, text=response)

@routes.get('/lp/{hash:.*}')
async def handle_lp(request):
	hash = request.match_info['hash'].rstrip('/')
	secret = ensure_get_params(request.query, 'secret')

	webhooks = request.app['ws2lp.webhooks']
	try: webhook = webhooks[hash]
	except KeyError as ex: raise web.HTTPNotFound(reason="Webhook is not registered.") from ex

	if (secret != webhook.secret): raise web.HTTPForbidden(reason="Incorrect secret.")

	res = list()
	for i in range(webhook.queue.qsize()):
		res.append(webhook.queue.get_nowait())#; webhook.queue.task_done()
	if (not res):
		res.append(await webhook.queue.get())#; webhook.queue.task_done()
		for i in range(webhook.queue.qsize()):
			res.append(webhook.queue.get_nowait())#; webhook.queue.task_done()

	return web.json_response(res, dumps=functools.partial(json.dumps, ensure_ascii=False))

app = web.Application(middlewares=(web.normalize_path_middleware(),))
app.add_routes(routes)
app['ws2lp.webhooks'] = dict()

def main():
	web.run_app(app)

if (__name__ == '__main__'): logstarted(); exit(main())
else: logimported()

# by Sdore, 2022
#  www.sdore.me
