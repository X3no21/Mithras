import json

from . import app, configs
import networkx as nx
import logging
from flask import request
from loguru import logger
import traceback


logger = logging.getLogger('graph_service')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


@app.route("/init-graph", methods=["GET"])
def init_graph():
    try:
        graph: nx.DiGraph = nx.empty_graph(0, create_using=nx.DiGraph())
        nx.write_graphml(graph, configs["DEFAULT"]['graph_file_path'])
        return json.dumps({"success": True}), 200, {"Content-Type": "application/json"}
    except:
        logger.error(traceback.format_exc())
        return json.dumps({"success": False}), 500, {"Content-Type": "application/json"}


@app.route("/update-graph", methods=["POST"])
def add_edge():
    try:
        logger.info("Received request to update graph")
        graph = nx.read_graphml(configs["DEFAULT"]['graph_file_path'])
        parent = request.form.get("parent", None)
        child = request.form.get("child", None)
        logger.info(f"Parent: {parent}, Child: {child}")
        
        if not parent or not child:
            logger.warning(f"Missing parent or child in request data. Parent: {parent}, Child: {child}")
            raise ValueError("Parent or child is missing in the request data")
        
        if not graph.has_node(parent):
            logger.info(f"Adding node {parent}")
            graph.add_node(parent)
        if not graph.has_node(child):
            logger.info(f"Adding node {child}")
            graph.add_node(child)
        
        nx.write_graphml(graph, configs["DEFAULT"]['graph_file_path'])
        response = {"success": True}
        logger.info(f"Response: {response}")
        return json.dumps(response), 200, {"Content-Type": "application/json"}
    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        response = {"success": False, "error": str(ve)}
        logger.info(f"Response: {response}")
        return json.dumps(response), 400, {"Content-Type": "application/json"}
    except Exception as e:
        logger.error(f"Exception: {traceback.format_exc()}")
        response = {"success": False, "error": str(e)}
        logger.info(f"Response: {response}")
        return json.dumps(response), 500, {"Content-Type": "application/json"}

